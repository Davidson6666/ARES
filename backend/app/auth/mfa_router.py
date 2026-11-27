"""Rotas de MFA (TOTP) e recuperação de conta (ADR 0005; complemento 3.2)."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

import structlog
from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from app.audit import service as audit
from app.auth import mfa, passwords, service
from app.auth.dependencies import (
    SESSION_COOKIE,
    allow_query,
    enforce_csrf,
    get_db,
    get_settings,
    require_json,
    require_session,
    utcnow,
)
from app.auth.models import MfaChallenge, RecoveryCode, User
from app.auth.service import AuthContext
from app.auth.session_flow import CHALLENGE_COOKIE, MeResponse, establish_session, request_id
from app.core.config import Settings
from app.core.errors import ApiError
from app.core.rate_limit import client_key

router = APIRouter(prefix="/api/v1")

log = structlog.get_logger("ares.mfa")

_NO_STORE = {"Cache-Control": "no-store"}


class CodeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # TOTP (6 dígitos) ou código de recuperação (10 caracteres com hífen).
    code: str = Field(min_length=6, max_length=16)


class DisableRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: str = Field(min_length=1, max_length=1024)
    code: str = Field(min_length=6, max_length=16)


class PasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: str = Field(min_length=1, max_length=1024)


class RecoveryConfirmRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=20, max_length=128)
    new_password: str = Field(min_length=1, max_length=1024)


class EnrollmentResponse(BaseModel):
    # Única vez em que o segredo existe em claro.
    secret: str
    otpauth_uri: str


class RecoveryCodesResponse(BaseModel):
    recovery_codes: list[str]


class StatusResponse(BaseModel):
    status: str


def _key(settings: Settings) -> bytes:
    try:
        return mfa.load_key(settings.mfa_key.get_secret_value() if settings.mfa_key else None)
    except mfa.MfaUnavailable:
        raise ApiError(
            503, "mfa_unavailable", "MFA indisponível. Contate o administrador."
        ) from None


def _busy() -> ApiError:
    return ApiError(503, "busy", "Serviço ocupado. Tente novamente.", headers={"Retry-After": "1"})


def _audit(
    db: DbSession,
    request: Request,
    action: str,
    result: audit.Result,
    user: User,
    reason: str | None = None,
    details: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> None:
    audit.record(
        db,
        action=action,
        result=result,
        actor_type="user",
        actor_user_id=user.id,
        resource_type="user",
        resource_id=str(user.id),
        reason=reason,
        request_id=request_id(request),
        details=details,
        now=now,
    )


def _reauthenticate(
    db: DbSession,
    request: Request,
    settings: Settings,
    user: User,
    password: str,
    action: str,
    now: datetime,
) -> None:
    """Confere a senha atual. Falha conta contra a conta (bloqueio progressivo)
    e é auditada; ``user`` é a linha da sessão corrente."""
    try:
        ok = (not service.is_locked(user, now)) and passwords.verify_password(
            user.password_hash, password
        )
    except passwords.HasherBusy:
        raise _busy() from None
    if ok:
        return
    locked = service.register_failed_attempt(user, settings, now)
    _audit(
        db,
        request,
        action,
        "failure",
        user,
        reason="reauthentication_failed",
        details={"locked_now": True} if locked else None,
        now=now,
    )
    db.commit()
    raise ApiError(401, "invalid_credentials", "Senha ou código inválidos.")


@dataclass
class Actor:
    """Quem está cadastrando o fator: uma sessão ativa, ou (papel administrativo
    sem TOTP) um desafio ``enroll`` criado pelo login."""

    user: User
    challenge: MfaChallenge | None = None


def _enroll_actor(request: Request, db: DbSession, settings: Settings) -> Actor:
    now = utcnow()
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        ctx = service.resolve_session(db, settings, token, now)
        if ctx is not None:
            enforce_csrf(request, db, ctx)
            return Actor(user=ctx.user)
    cookie = request.cookies.get(CHALLENGE_COOKIE)
    if cookie:
        challenge = mfa.load_challenge(db, cookie, "enroll", now)
        if challenge is not None:
            user = db.get(User, challenge.user_id)
            if user is not None and user.status == "active":
                return Actor(user=user, challenge=challenge)
    raise ApiError(401, "unauthenticated", "Autenticação necessária.")


@router.post(
    "/auth/mfa/enroll",
    status_code=201,
    response_model=EnrollmentResponse,
    dependencies=[Depends(allow_query())],
)
def enroll(
    request: Request,
    response: Response,
    body: PasswordRequest | None = None,
    db: DbSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> EnrollmentResponse:
    key = _key(settings)
    actor = _enroll_actor(request, db, settings)
    now = utcnow()
    if actor.challenge is None:
        # Sessão (usuário sem MFA): a sessão sozinha não basta para virar dono
        # do segundo fator; exige a senha atual. No desafio, a senha acabou de
        # ser conferida no login.
        if body is None:
            raise ApiError(422, "password_required", "Informe a senha atual.")
        _reauthenticate(db, request, settings, actor.user, body.password, "mfa.enroll", now)
    if mfa.active_factor(db, actor.user.id) is not None:
        raise ApiError(409, "mfa_already_enrolled", "O MFA já está ativo para esta conta.")
    enrollment = mfa.start_enrollment(db, key, actor.user, now)
    _audit(db, request, "mfa.enroll", "success", actor.user, now=now)
    db.commit()
    response.headers.update(_NO_STORE)
    return EnrollmentResponse(secret=enrollment.secret, otpauth_uri=enrollment.otpauth_uri)


@router.post(
    "/auth/mfa/confirm",
    response_model=RecoveryCodesResponse,
    dependencies=[Depends(require_json), Depends(allow_query())],
)
def confirm(
    body: CodeRequest,
    request: Request,
    response: Response,
    db: DbSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> RecoveryCodesResponse:
    key = _key(settings)
    actor = _enroll_actor(request, db, settings)
    now = utcnow()
    try:
        confirmed = mfa.confirm_enrollment(db, key, actor.user.id, body.code, now)
    except IntegrityError:
        # Dois cadastros concorrentes: o índice único de fator ativo barrou o segundo.
        db.rollback()
        raise ApiError(
            409, "mfa_already_enrolled", "O MFA já está ativo para esta conta."
        ) from None
    if not confirmed:
        burned = mfa.register_failure(actor.challenge, now) if actor.challenge else False
        _audit(
            db,
            request,
            "mfa.confirm",
            "failure",
            actor.user,
            reason="invalid_code",
            details={"burned": True} if burned else None,
            now=now,
        )
        db.commit()
        raise ApiError(401, "invalid_code", "Código inválido.")
    try:
        codes = mfa.issue_recovery_codes(db, actor.user.id, now)
    except passwords.HasherBusy:
        raise _busy() from None
    _audit(db, request, "mfa.confirm", "success", actor.user, now=now)
    _audit(db, request, "mfa.recovery_codes_issued", "success", actor.user, now=now)
    response.headers.update(_NO_STORE)
    if actor.challenge is not None:
        # Administrador cadastrando o primeiro TOTP: o cadastro conclui o login.
        actor.challenge.used_at = now
        establish_session(db, settings, request, response, actor.user, now, method="totp_enroll")
    else:
        db.commit()
    return RecoveryCodesResponse(recovery_codes=codes)


@router.post(
    "/auth/mfa/verify",
    response_model=MeResponse,
    dependencies=[Depends(require_json), Depends(allow_query())],
)
def verify(
    body: CodeRequest,
    request: Request,
    response: Response,
    db: DbSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> MeResponse:
    key = _key(settings)
    retry_after = request.app.state.mfa_limiter.hit(
        client_key(request.client.host if request.client else None)
    )
    if retry_after is not None:
        log.warning("mfa.rate_limited", request_id=request_id(request))
        raise ApiError(
            429,
            "rate_limited",
            "Muitas tentativas. Tente novamente mais tarde.",
            headers={"Retry-After": str(retry_after)},
        )
    now = utcnow()
    cookie = request.cookies.get(CHALLENGE_COOKIE)
    challenge = mfa.load_challenge(db, cookie, "verify", now) if cookie else None
    # Trava a linha do usuário: palpites simultâneos se serializam, o contador
    # de falhas não perde atualização, e uma recuperação em andamento espera.
    user = (
        db.scalar(select(User).where(User.id == challenge.user_id).with_for_update())
        if challenge
        else None
    )
    if challenge is None or user is None or user.status != "active" or service.is_locked(user, now):
        raise ApiError(401, "unauthenticated", "Desafio inválido ou expirado.")

    factor = mfa.active_factor(db, user.id, lock=True)
    method: str | None = None
    try:
        if factor is not None and mfa.accept_code(key, factor, body.code, now):
            method = "totp"
        elif mfa.consume_recovery_code(db, user.id, body.code, now):
            method = "recovery_code"
    except passwords.HasherBusy:
        raise _busy() from None

    if method is None:
        burned = mfa.register_failure(challenge, now)
        # Conta contra a CONTA, não só contra o desafio: refazer a senha não
        # dá palpites novos de graça.
        locked = service.register_failed_attempt(user, settings, now)
        details: dict[str, Any] = {}
        if burned:
            details["burned"] = True
        if locked:
            details["locked_now"] = True
        _audit(
            db,
            request,
            "mfa.verify",
            "failure",
            user,
            reason="invalid_code",
            details=details or None,
            now=now,
        )
        db.commit()
        raise ApiError(401, "invalid_code", "Código inválido.")

    challenge.used_at = now
    _audit(db, request, "mfa.verify", "success", user, details={"method": method}, now=now)
    return establish_session(db, settings, request, response, user, now, method=method)


@router.delete(
    "/auth/mfa",
    status_code=204,
    dependencies=[Depends(require_json), Depends(allow_query())],
)
def disable(
    body: DisableRequest,
    request: Request,
    response: Response,
    ctx: AuthContext = Depends(require_session),
    db: DbSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Response:
    key = _key(settings)
    now = utcnow()
    user = ctx.user
    if mfa.is_admin(db, user.id):
        _audit(db, request, "mfa.disable", "denied", user, reason="admin_role", now=now)
        db.commit()
        raise ApiError(403, "mfa_required_for_role", "O papel desta conta exige MFA.")
    _reauthenticate(db, request, settings, user, body.password, "mfa.disable", now)
    factor = mfa.active_factor(db, user.id, lock=True)
    if factor is None or not mfa.accept_code(key, factor, body.code, now):
        service.register_failed_attempt(user, settings, now)
        _audit(
            db, request, "mfa.disable", "failure", user, reason="reauthentication_failed", now=now
        )
        db.commit()
        raise ApiError(401, "invalid_credentials", "Senha ou código inválidos.")
    factor.status = "revoked"
    factor.revoked_at = now
    # Os códigos de recuperação pertenciam a esse fator.
    db.execute(
        update(RecoveryCode)
        .where(RecoveryCode.user_id == user.id, RecoveryCode.used_at.is_(None))
        .values(used_at=now)
    )
    _audit(db, request, "mfa.disable", "success", user, now=now)
    db.commit()
    response.status_code = 204
    return response


@router.post(
    "/auth/recovery-codes",
    status_code=201,
    response_model=RecoveryCodesResponse,
    dependencies=[Depends(require_json), Depends(allow_query())],
)
def new_recovery_codes(
    body: PasswordRequest,
    request: Request,
    response: Response,
    ctx: AuthContext = Depends(require_session),
    db: DbSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> RecoveryCodesResponse:
    now = utcnow()
    user = ctx.user
    if mfa.active_factor(db, user.id) is None:
        raise ApiError(409, "mfa_not_enabled", "Ative o MFA antes de gerar códigos de recuperação.")
    _reauthenticate(db, request, settings, user, body.password, "mfa.recovery_codes_issued", now)
    try:
        codes = mfa.issue_recovery_codes(db, user.id, now)
    except passwords.HasherBusy:
        raise _busy() from None
    _audit(db, request, "mfa.recovery_codes_issued", "success", user, now=now)
    db.commit()
    response.headers.update(_NO_STORE)
    return RecoveryCodesResponse(recovery_codes=codes)


@router.post(
    "/auth/recovery/confirm",
    response_model=StatusResponse,
    dependencies=[Depends(require_json), Depends(allow_query())],
)
def recovery_confirm(
    body: RecoveryConfirmRequest,
    request: Request,
    db: DbSession = Depends(get_db),
) -> StatusResponse:
    retry_after = request.app.state.recovery_limiter.hit(
        client_key(request.client.host if request.client else None)
    )
    if retry_after is not None:
        raise ApiError(
            429,
            "rate_limited",
            "Muitas tentativas. Tente novamente mais tarde.",
            headers={"Retry-After": str(retry_after)},
        )
    now = utcnow()
    # O tamanho da senha é conferido ANTES de olhar o token: o 422 não pode
    # servir de oráculo de "este token existe". (Senha igual ao e-mail só dá
    # para saber com o usuário, e é conferida depois.)
    length_violation = passwords.policy_violation(body.new_password, "")
    if length_violation is not None:
        raise ApiError(422, length_violation, "Senha fora da política (12 a 128 caracteres).")
    invalid = ApiError(401, "invalid_recovery", "Token de recuperação inválido ou expirado.")
    try:
        user = mfa.use_recovery_token(db, body.token, now)
        if user is None:
            # Mesmo custo de uma troca de senha válida, para o tempo não
            # distinguir token inexistente, usado ou expirado.
            passwords.verify_dummy(body.new_password)
            # Só log: sob ataque, não gravar uma linha permanente por tentativa (ADR 0004).
            log.warning("recovery.invalid_token", request_id=request_id(request))
            raise invalid
        violation = passwords.policy_violation(body.new_password, user.email)
        if violation is not None:
            # Sem commit: o token não é consumido por uma senha recusada.
            raise ApiError(422, violation, "Senha fora da política (12 a 128 caracteres).")
        user.password_hash = passwords.hash_password(body.new_password)
    except passwords.HasherBusy:
        raise _busy() from None
    service.clear_failures(user, now)
    # Recuperar a senha encerra todas as sessões e desafios pendentes. O MFA
    # NÃO é desativado: a recuperação não pode contornar o segundo fator.
    mfa.revoke_all_sessions(db, user.id, now)
    db.execute(
        update(MfaChallenge)
        .where(MfaChallenge.user_id == user.id, MfaChallenge.used_at.is_(None))
        .values(used_at=now)
    )
    _audit(db, request, "auth.recovery_used", "success", user, now=now)
    db.commit()
    return StatusResponse(status="password_changed")

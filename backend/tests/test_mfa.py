"""MFA (TOTP) e recuperação de conta (ADR 0005)."""

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, text, update
from sqlalchemy.orm import Session as DbSession

from app import cli
from app.auth import crypto, mfa, passwords
from app.auth.dependencies import CSRF_HEADER, SESSION_COOKIE
from app.auth.models import MfaChallenge, MfaFactor, RecoveryCode, RecoveryToken, Session, User
from app.auth.session_flow import CHALLENGE_COOKIE
from app.main import create_app
from tests.test_auth import (
    PASSWORD,
    TEST_MFA_KEY,
    _settings,
    add_factor,
    fresh_code,
    login_mfa,
    make_user,
)

pytestmark = pytest.mark.db

NEW_PASSWORD = "uma-senha-nova-bem-longa"


@pytest.fixture
def client(app_engine: Engine) -> Iterator[TestClient]:
    app = create_app(_settings(), engine=app_engine)
    with TestClient(app, base_url="https://testserver", raise_server_exceptions=False) as c:
        yield c


def login_step1(client: TestClient, email: str, password: str = PASSWORD):  # type: ignore[no-untyped-def]
    return client.post("/api/v1/auth/login", json={"email": email, "password": password})


def audit_actions(engine: Engine) -> list[tuple[str, str]]:
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT action, result FROM audit_logs ORDER BY id")).all()
    return [(r[0], r[1]) for r in rows]


# --- cifra ------------------------------------------------------------------


def test_crypto_roundtrip_and_binding() -> None:
    key = crypto.parse_key(TEST_MFA_KEY)
    uid = uuid.uuid4()
    blob = crypto.encrypt_secret(key, uid, "totp", "JBSWY3DPEHPK3PXP")
    assert b"JBSWY3DPEHPK3PXP" not in blob
    assert crypto.decrypt_secret(key, uid, "totp", blob) == "JBSWY3DPEHPK3PXP"
    # Blob copiado para outro usuário, ou outra chave, não decifra.
    with pytest.raises(crypto.MfaCryptoError):
        crypto.decrypt_secret(key, uuid.uuid4(), "totp", blob)
    with pytest.raises(crypto.MfaCryptoError):
        crypto.decrypt_secret(bytes(32), uid, "totp", blob)
    # Cifrar duas vezes o mesmo valor dá blobs diferentes (nonce aleatório).
    assert crypto.encrypt_secret(key, uid, "totp", "X") != crypto.encrypt_secret(
        key, uid, "totp", "X"
    )


@pytest.mark.parametrize("raw", ["", "não-base64!", "QUJD", "A" * 100])
def test_crypto_rejects_bad_keys(raw: str) -> None:
    with pytest.raises(crypto.MfaCryptoError):
        crypto.parse_key(raw)


def test_generated_key_is_valid() -> None:
    assert len(crypto.parse_key(crypto.generate_key())) == 32


# --- cadastro e login de administrador --------------------------------------


def test_admin_without_factor_must_enroll_and_gets_no_session(
    client: TestClient, admin_engine: Engine
) -> None:
    make_user(admin_engine, "adm@ares.test", roles=("super_admin",))
    r = login_step1(client, "adm@ares.test")
    assert r.status_code == 200
    assert r.json() == {"status": "mfa_required", "purpose": "enroll"}
    assert SESSION_COOKIE not in client.cookies
    cookie = r.headers["set-cookie"].lower()
    for attr in ("httponly", "secure", "samesite=strict", "path=/"):
        assert attr in cookie
    assert "domain=" not in cookie
    assert client.get("/api/v1/me").status_code == 401


def test_enroll_confirm_completes_login_and_protects_secret(
    client: TestClient, admin_engine: Engine
) -> None:
    uid = make_user(admin_engine, "adm@ares.test", roles=("super_admin",))
    login_step1(client, "adm@ares.test")

    r = client.post("/api/v1/auth/mfa/enroll")
    assert r.status_code == 201
    assert r.headers["cache-control"] == "no-store"
    secret = r.json()["secret"]
    assert r.json()["otpauth_uri"].startswith("otpauth://totp/ARES:adm%40ares.test")
    assert "issuer=ARES" in r.json()["otpauth_uri"]

    # Segredo nunca em claro no banco.
    with admin_engine.connect() as conn:
        dump = conn.execute(text("SELECT row_to_json(f)::text FROM mfa_factors f")).scalar_one()
    assert secret not in dump
    with DbSession(admin_engine) as db:
        factor = db.scalar(select(MfaFactor))
        assert factor is not None
        assert (factor.status, factor.secret_ref) == ("pending", "env:v1")

    bad = client.post("/api/v1/auth/mfa/confirm", json={"code": "000000"})
    assert bad.status_code == 401 and bad.json()["code"] == "invalid_code"

    r = client.post("/api/v1/auth/mfa/confirm", json={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200
    codes = r.json()["recovery_codes"]
    assert len(codes) == len(set(codes)) == 10
    assert all(len(c) == 11 and c[5] == "-" for c in codes)
    assert client.get("/api/v1/me").status_code == 200  # o cadastro concluiu o login

    with DbSession(admin_engine) as db:
        assert db.scalar(select(MfaFactor.status)) == "active"
        hashes = db.scalars(select(RecoveryCode.code_hash)).all()
        assert len(hashes) == 10 and all(h.startswith("$argon2id$") for h in hashes)
        assert all(c.replace("-", "") not in h for c in codes for h in hashes)
    assert audit_actions(admin_engine) == [
        ("mfa.challenge", "success"),
        ("mfa.enroll", "success"),
        ("mfa.confirm", "failure"),
        ("mfa.confirm", "success"),
        ("mfa.recovery_codes_issued", "success"),
        ("auth.login", "success"),
    ]
    assert uid  # usado só para criar o usuário


def test_enroll_when_already_active_is_409(client: TestClient, admin_engine: Engine) -> None:
    uid = make_user(admin_engine, "u@ares.test", roles=("viewer",))
    secret = add_factor(admin_engine, uid)
    csrf = str(login_mfa(client, admin_engine, "u@ares.test", secret)["csrf_token"])
    r = client.post(
        "/api/v1/auth/mfa/enroll", json={"password": PASSWORD}, headers={CSRF_HEADER: csrf}
    )
    assert r.status_code == 409 and r.json()["code"] == "mfa_already_enrolled"


def test_enroll_by_session_requires_csrf(client: TestClient, admin_engine: Engine) -> None:
    make_user(admin_engine, "v@ares.test", roles=("viewer",))
    client.post("/api/v1/auth/login", json={"email": "v@ares.test", "password": PASSWORD})
    assert client.post("/api/v1/auth/mfa/enroll").status_code == 403


def test_enroll_without_any_credential_is_401(client: TestClient) -> None:
    assert client.post("/api/v1/auth/mfa/enroll").status_code == 401
    assert client.post("/api/v1/auth/mfa/confirm", json={"code": "123456"}).status_code == 401


# --- login com fator ativo --------------------------------------------------


def test_user_with_factor_gets_challenge_not_session(
    client: TestClient, admin_engine: Engine
) -> None:
    uid = make_user(admin_engine, "f@ares.test", roles=("viewer",))
    add_factor(admin_engine, uid)
    r = login_step1(client, "f@ares.test")
    assert r.json() == {"status": "mfa_required", "purpose": "verify"}
    assert SESSION_COOKIE not in client.cookies
    with DbSession(admin_engine) as db:
        assert db.scalar(select(Session.id)) is None


def test_verify_success_creates_session_and_clears_challenge(
    client: TestClient, admin_engine: Engine
) -> None:
    uid = make_user(admin_engine, "ok@ares.test", roles=("viewer",))
    secret = add_factor(admin_engine, uid)
    body = login_mfa(client, admin_engine, "ok@ares.test", secret)
    assert body["email"] == "ok@ares.test"
    assert CHALLENGE_COOKIE not in client.cookies
    assert client.get("/api/v1/me").status_code == 200
    assert ("mfa.verify", "success") in audit_actions(admin_engine)


def test_wrong_code_fails_and_five_failures_burn_the_challenge(
    client: TestClient, admin_engine: Engine
) -> None:
    uid = make_user(admin_engine, "w@ares.test", roles=("viewer",))
    secret = add_factor(admin_engine, uid)
    login_step1(client, "w@ares.test")
    for _ in range(5):
        r = client.post("/api/v1/auth/mfa/verify", json={"code": "000000"})
        assert r.status_code == 401 and r.json()["code"] == "invalid_code"
    # Esgotado: nem o código certo vale mais, e é preciso refazer a senha.
    r = client.post("/api/v1/auth/mfa/verify", json={"code": fresh_code(admin_engine, secret)})
    assert r.status_code == 401 and r.json()["code"] == "unauthenticated"
    assert SESSION_COOKIE not in client.cookies


def test_totp_code_cannot_be_reused(client: TestClient, admin_engine: Engine) -> None:
    """9.2: o mesmo código TOTP duas vezes; a segunda falha."""
    uid = make_user(admin_engine, "re@ares.test", roles=("viewer",))
    secret = add_factor(admin_engine, uid)
    code = fresh_code(admin_engine, secret)

    login_step1(client, "re@ares.test")
    assert client.post("/api/v1/auth/mfa/verify", json={"code": code}).status_code == 200

    client.cookies.clear()
    login_step1(client, "re@ares.test")
    r = client.post("/api/v1/auth/mfa/verify", json={"code": code})
    assert r.status_code == 401 and r.json()["code"] == "invalid_code"


def test_old_step_is_rejected_after_newer_one_used(
    client: TestClient, admin_engine: Engine
) -> None:
    uid = make_user(admin_engine, "old@ares.test", roles=("viewer",))
    secret = add_factor(admin_engine, uid)
    now = datetime.now(UTC)
    totp = pyotp.TOTP(secret)
    newer = totp.at(now + timedelta(seconds=30))
    older = totp.at(now - timedelta(seconds=30))
    fresh_code(admin_engine, secret)  # zera last_used_step
    login_step1(client, "old@ares.test")
    assert client.post("/api/v1/auth/mfa/verify", json={"code": newer}).status_code == 200
    client.cookies.clear()
    login_step1(client, "old@ares.test")
    assert client.post("/api/v1/auth/mfa/verify", json={"code": older}).status_code == 401


@pytest.mark.parametrize("code", ["12345", "1234567", "abcdef", "12 456", "１２３４５６"])
def test_malformed_codes_are_rejected(client: TestClient, admin_engine: Engine, code: str) -> None:
    uid = make_user(admin_engine, "m@ares.test", roles=("viewer",))
    add_factor(admin_engine, uid)
    login_step1(client, "m@ares.test")
    r = client.post("/api/v1/auth/mfa/verify", json={"code": code})
    assert r.status_code in (401, 422)


def test_expired_challenge_is_rejected(client: TestClient, admin_engine: Engine) -> None:
    uid = make_user(admin_engine, "ex@ares.test", roles=("viewer",))
    secret = add_factor(admin_engine, uid)
    login_step1(client, "ex@ares.test")
    with DbSession(admin_engine) as db:
        db.execute(update(MfaChallenge).values(expires_at=datetime.now(UTC) - timedelta(seconds=1)))
        db.commit()
    r = client.post("/api/v1/auth/mfa/verify", json={"code": fresh_code(admin_engine, secret)})
    assert r.status_code == 401


def test_verify_without_challenge_cookie_is_401(client: TestClient) -> None:
    r = client.post("/api/v1/auth/mfa/verify", json={"code": "123456"})
    assert r.status_code == 401 and r.json()["code"] == "unauthenticated"


def test_new_login_invalidates_previous_challenge(client: TestClient, admin_engine: Engine) -> None:
    uid = make_user(admin_engine, "two@ares.test", roles=("viewer",))
    secret = add_factor(admin_engine, uid)
    login_step1(client, "two@ares.test")
    first = client.cookies.get(CHALLENGE_COOKIE)
    login_step1(client, "two@ares.test")
    client.cookies.clear()
    client.cookies.set(CHALLENGE_COOKIE, str(first))
    r = client.post("/api/v1/auth/mfa/verify", json={"code": fresh_code(admin_engine, secret)})
    assert r.status_code == 401


def test_challenge_token_is_stored_only_as_hash(client: TestClient, admin_engine: Engine) -> None:
    uid = make_user(admin_engine, "h@ares.test", roles=("viewer",))
    add_factor(admin_engine, uid)
    login_step1(client, "h@ares.test")
    token = client.cookies.get(CHALLENGE_COOKIE)
    assert token
    with admin_engine.connect() as conn:
        dump = conn.execute(text("SELECT row_to_json(c)::text FROM mfa_challenges c")).scalar_one()
    assert token not in dump


def test_login_without_mfa_key_is_503_for_mfa_accounts(
    app_engine: Engine, admin_engine: Engine
) -> None:
    uid = make_user(admin_engine, "nk@ares.test", roles=("viewer",))
    add_factor(admin_engine, uid)
    make_user(admin_engine, "nk-admin@ares.test", roles=("super_admin",))
    app = create_app(_settings(mfa_key=None), engine=app_engine)
    with TestClient(app, base_url="https://testserver") as c:
        for email in ("nk@ares.test", "nk-admin@ares.test"):
            r = c.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
            assert r.status_code == 503 and r.json()["code"] == "mfa_unavailable"
            assert SESSION_COOKIE not in c.cookies and CHALLENGE_COOKIE not in c.cookies
        # Conta sem MFA e sem papel administrativo continua entrando.
        make_user(admin_engine, "plain@ares.test", roles=("viewer",))
        r = c.post("/api/v1/auth/login", json={"email": "plain@ares.test", "password": PASSWORD})
        assert r.status_code == 200 and "csrf_token" in r.json()


# --- códigos de recuperação -------------------------------------------------


def _issue_codes(engine: Engine, uid: uuid.UUID) -> list[str]:
    with DbSession(engine) as db:
        codes = mfa.issue_recovery_codes(db, uid, datetime.now(UTC))
        db.commit()
    return codes


def test_recovery_code_logs_in_once(client: TestClient, admin_engine: Engine) -> None:
    uid = make_user(admin_engine, "rc@ares.test", roles=("viewer",))
    add_factor(admin_engine, uid)
    codes = _issue_codes(admin_engine, uid)

    login_step1(client, "rc@ares.test")
    r = client.post("/api/v1/auth/mfa/verify", json={"code": codes[0]})
    assert r.status_code == 200
    assert ("mfa.verify", "success") in audit_actions(admin_engine)

    client.cookies.clear()
    login_step1(client, "rc@ares.test")
    r = client.post("/api/v1/auth/mfa/verify", json={"code": codes[0]})
    assert r.status_code == 401  # uso único
    r = client.post("/api/v1/auth/mfa/verify", json={"code": codes[1].upper()})
    assert r.status_code == 200  # maiúsculas e hífen são normalizados


def test_new_batch_invalidates_previous_batch(client: TestClient, admin_engine: Engine) -> None:
    uid = make_user(admin_engine, "nb@ares.test", roles=("viewer",))
    add_factor(admin_engine, uid)
    old = _issue_codes(admin_engine, uid)
    _issue_codes(admin_engine, uid)
    login_step1(client, "nb@ares.test")
    assert client.post("/api/v1/auth/mfa/verify", json={"code": old[0]}).status_code == 401


def test_regenerate_recovery_codes_requires_password_and_factor(
    client: TestClient, admin_engine: Engine
) -> None:
    uid = make_user(admin_engine, "rg@ares.test", roles=("viewer",))
    secret = add_factor(admin_engine, uid)
    csrf = str(login_mfa(client, admin_engine, "rg@ares.test", secret)["csrf_token"])
    h = {CSRF_HEADER: csrf}
    r = client.post("/api/v1/auth/recovery-codes", json={"password": "errada-errada"}, headers=h)
    assert r.status_code == 401
    r = client.post("/api/v1/auth/recovery-codes", json={"password": PASSWORD}, headers=h)
    assert r.status_code == 201 and len(r.json()["recovery_codes"]) == 10
    assert r.headers["cache-control"] == "no-store"
    assert (
        client.post("/api/v1/auth/recovery-codes", json={"password": PASSWORD}).status_code == 403
    )


def test_regenerate_without_factor_is_409(client: TestClient, admin_engine: Engine) -> None:
    make_user(admin_engine, "nf@ares.test", roles=("viewer",))
    csrf = str(
        client.post(
            "/api/v1/auth/login", json={"email": "nf@ares.test", "password": PASSWORD}
        ).json()["csrf_token"]
    )
    r = client.post(
        "/api/v1/auth/recovery-codes", json={"password": PASSWORD}, headers={CSRF_HEADER: csrf}
    )
    assert r.status_code == 409 and r.json()["code"] == "mfa_not_enabled"


# --- desativar MFA ----------------------------------------------------------


def test_disable_requires_password_and_code(client: TestClient, admin_engine: Engine) -> None:
    uid = make_user(admin_engine, "d@ares.test", roles=("viewer",))
    secret = add_factor(admin_engine, uid)
    codes = _issue_codes(admin_engine, uid)
    csrf = str(login_mfa(client, admin_engine, "d@ares.test", secret)["csrf_token"])
    h = {CSRF_HEADER: csrf}

    def delete(payload: dict[str, str]):  # type: ignore[no-untyped-def]
        return client.request("DELETE", "/api/v1/auth/mfa", json=payload, headers=h)

    assert (
        delete({"password": "errada-errada", "code": fresh_code(admin_engine, secret)}).status_code
        == 401
    )
    assert delete({"password": PASSWORD, "code": "000000"}).status_code == 401
    assert client.request(
        "DELETE", "/api/v1/auth/mfa", json={"password": PASSWORD, "code": "1"}
    ).status_code in (403, 422)
    assert (
        delete({"password": PASSWORD, "code": fresh_code(admin_engine, secret)}).status_code == 204
    )

    with DbSession(admin_engine) as db:
        assert db.scalar(select(MfaFactor.status)) == "revoked"
        assert db.scalar(select(RecoveryCode.id).where(RecoveryCode.used_at.is_(None))) is None
    # Sem fator ativo, o login volta a ser só de senha, e os códigos antigos não valem.
    client.cookies.clear()
    r = login_step1(client, "d@ares.test")
    assert r.status_code == 200 and "csrf_token" in r.json()
    assert codes  # lote existia


def test_admin_cannot_disable_mfa(client: TestClient, admin_engine: Engine) -> None:
    uid = make_user(admin_engine, "adm2@ares.test", roles=("security_admin",))
    secret = add_factor(admin_engine, uid)
    csrf = str(login_mfa(client, admin_engine, "adm2@ares.test", secret)["csrf_token"])
    r = client.request(
        "DELETE",
        "/api/v1/auth/mfa",
        json={"password": PASSWORD, "code": fresh_code(admin_engine, secret)},
        headers={CSRF_HEADER: csrf},
    )
    assert r.status_code == 403 and r.json()["code"] == "mfa_required_for_role"
    assert ("mfa.disable", "denied") in audit_actions(admin_engine)
    with DbSession(admin_engine) as db:
        assert db.scalar(select(MfaFactor.status)) == "active"


# --- recuperação de conta ---------------------------------------------------


def test_recovery_flow_changes_password_and_kills_sessions(
    client: TestClient, admin_engine: Engine, app_engine: Engine
) -> None:
    uid = make_user(admin_engine, "rec@ares.test", roles=("viewer",))
    client.post("/api/v1/auth/login", json={"email": "rec@ares.test", "password": PASSWORD})
    assert client.get("/api/v1/me").status_code == 200  # sessão anterior à recuperação

    token = cli.issue_recovery(admin_engine, "REC@ares.test")
    assert len(token) >= 40
    with admin_engine.connect() as conn:
        dump = conn.execute(text("SELECT row_to_json(t)::text FROM recovery_tokens t")).scalar_one()
    assert token not in dump  # só o hash

    other = TestClient(create_app(_settings(), engine=app_engine), base_url="https://testserver")
    r = other.post(
        "/api/v1/auth/recovery/confirm", json={"token": token, "new_password": NEW_PASSWORD}
    )
    assert r.status_code == 200 and r.json() == {"status": "password_changed"}
    assert client.get("/api/v1/me").status_code == 401  # sessão antiga encerrada

    old = client.post("/api/v1/auth/login", json={"email": "rec@ares.test", "password": PASSWORD})
    assert old.status_code == 401
    new = client.post(
        "/api/v1/auth/login", json={"email": "rec@ares.test", "password": NEW_PASSWORD}
    )
    assert new.status_code == 200
    actions = audit_actions(admin_engine)
    assert ("auth.recovery_issued", "success") in actions
    assert ("auth.recovery_used", "success") in actions
    assert uid


def test_recovery_token_cannot_be_reused(client: TestClient, admin_engine: Engine) -> None:
    """9.2: token reutilizado devolve 401."""
    make_user(admin_engine, "ru@ares.test")
    token = cli.issue_recovery(admin_engine, "ru@ares.test")
    payload = {"token": token, "new_password": NEW_PASSWORD}
    assert client.post("/api/v1/auth/recovery/confirm", json=payload).status_code == 200
    r = client.post("/api/v1/auth/recovery/confirm", json=payload)
    assert r.status_code == 401 and r.json()["code"] == "invalid_recovery"


def test_recovery_failures_are_indistinguishable_and_spend_argon2_time(  # tempo: proxy por espião
    client: TestClient, admin_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_user(admin_engine, "ind@ares.test")
    used = cli.issue_recovery(admin_engine, "ind@ares.test")
    client.post("/api/v1/auth/recovery/confirm", json={"token": used, "new_password": NEW_PASSWORD})
    expired = cli.issue_recovery(admin_engine, "ind@ares.test")
    with DbSession(admin_engine) as db:
        db.execute(
            update(RecoveryToken)
            .where(RecoveryToken.used_at.is_(None))
            .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        db.commit()
    make_user(admin_engine, "off@ares.test", status="disabled")
    with DbSession(admin_engine) as db:
        db.add(
            RecoveryToken(
                id=uuid.uuid4(),
                user_id=db.scalar(select(User.id).where(User.email == "off@ares.test")),
                token_hash=mfa._sha256("t" * 40),
                created_at=datetime.now(UTC),
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
            )
        )
        db.commit()

    calls: list[str] = []
    original = passwords.verify_dummy

    def spy(password: str) -> None:
        calls.append(password)
        original(password)

    monkeypatch.setattr(passwords, "verify_dummy", spy)
    bodies = []
    for token in (used, expired, "x" * 43, "t" * 40):
        r = client.post(
            "/api/v1/auth/recovery/confirm", json={"token": token, "new_password": NEW_PASSWORD}
        )
        assert r.status_code == 401
        bodies.append({k: v for k, v in r.json().items() if k != "request_id"})
    assert all(b == bodies[0] for b in bodies) and bodies[0]["code"] == "invalid_recovery"
    assert len(calls) == 4


def test_recovery_rejects_weak_password_without_consuming_token(
    client: TestClient, admin_engine: Engine
) -> None:
    make_user(admin_engine, "weak@ares.test")
    token = cli.issue_recovery(admin_engine, "weak@ares.test")
    r = client.post("/api/v1/auth/recovery/confirm", json={"token": token, "new_password": "curta"})
    assert r.status_code == 422 and r.json()["code"] == "password_too_short"
    ok = client.post(
        "/api/v1/auth/recovery/confirm", json={"token": token, "new_password": NEW_PASSWORD}
    )
    assert ok.status_code == 200  # o token continuava válido


def test_recovery_does_not_disable_mfa(client: TestClient, admin_engine: Engine) -> None:
    uid = make_user(admin_engine, "keep@ares.test", roles=("viewer",))
    add_factor(admin_engine, uid)
    token = cli.issue_recovery(admin_engine, "keep@ares.test")
    client.post(
        "/api/v1/auth/recovery/confirm", json={"token": token, "new_password": NEW_PASSWORD}
    )
    r = login_step1(client, "keep@ares.test", NEW_PASSWORD)
    assert r.json() == {"status": "mfa_required", "purpose": "verify"}  # segundo fator continua
    with DbSession(admin_engine) as db:
        assert db.scalar(select(MfaFactor.status)) == "active"


def test_recovery_resets_lockout(client: TestClient, admin_engine: Engine) -> None:
    make_user(admin_engine, "lk@ares.test")
    for _ in range(5):
        login_step1(client, "lk@ares.test", "errada-errada")
    token = cli.issue_recovery(admin_engine, "lk@ares.test")
    client.post(
        "/api/v1/auth/recovery/confirm", json={"token": token, "new_password": NEW_PASSWORD}
    )
    assert login_step1(client, "lk@ares.test", NEW_PASSWORD).status_code == 200


def test_new_recovery_token_invalidates_previous(client: TestClient, admin_engine: Engine) -> None:
    make_user(admin_engine, "two-t@ares.test")
    first = cli.issue_recovery(admin_engine, "two-t@ares.test")
    cli.issue_recovery(admin_engine, "two-t@ares.test")
    r = client.post(
        "/api/v1/auth/recovery/confirm", json={"token": first, "new_password": NEW_PASSWORD}
    )
    assert r.status_code == 401


def test_recovery_rate_limit(app_engine: Engine) -> None:
    app = create_app(_settings(recovery_rate_limit_per_minute=2), engine=app_engine)
    with TestClient(app, base_url="https://testserver") as c:
        payload = {"token": "x" * 43, "new_password": NEW_PASSWORD}
        assert c.post("/api/v1/auth/recovery/confirm", json=payload).status_code == 401
        assert c.post("/api/v1/auth/recovery/confirm", json=payload).status_code == 401
        r = c.post("/api/v1/auth/recovery/confirm", json=payload)
        assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1


def test_recovery_rejects_extra_fields_and_non_json(client: TestClient) -> None:
    r = client.post(
        "/api/v1/auth/recovery/confirm",
        json={"token": "x" * 43, "new_password": NEW_PASSWORD, "role": "super_admin"},
    )
    assert r.status_code == 422
    r = client.post(
        "/api/v1/auth/recovery/confirm",
        content=b"token=x",
        headers={"Content-Type": "text/plain"},
    )
    assert r.status_code == 400


def test_cli_issue_recovery_unknown_or_disabled_account(admin_engine: Engine) -> None:
    make_user(admin_engine, "dis@ares.test", status="disabled")
    for email in ("naoexiste@ares.test", "dis@ares.test"):
        with pytest.raises(cli.CliError):
            cli.issue_recovery(admin_engine, email)


def test_cli_generate_mfa_key(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["generate-mfa-key"]) == 0
    printed = capsys.readouterr().out.strip()
    assert len(crypto.parse_key(printed)) == 32


def test_secrets_never_reach_audit_or_logs(client: TestClient, admin_engine: Engine) -> None:
    uid = make_user(admin_engine, "sec@ares.test", roles=("viewer",))
    secret = add_factor(admin_engine, uid)
    codes = _issue_codes(admin_engine, uid)
    login_mfa(client, admin_engine, "sec@ares.test", secret)
    token = cli.issue_recovery(admin_engine, "sec@ares.test")
    client.post(
        "/api/v1/auth/recovery/confirm", json={"token": token, "new_password": NEW_PASSWORD}
    )
    with admin_engine.connect() as conn:
        dump = str(conn.execute(text("SELECT json_agg(a)::text FROM audit_logs a")).scalar())
    for forbidden in (secret, token, NEW_PASSWORD, PASSWORD, *codes, TEST_MFA_KEY):
        assert forbidden not in dump


# --- achados da revisão de conformidade -------------------------------------


def test_confirm_revokes_previous_active_factor(client: TestClient, admin_engine: Engine) -> None:
    uid = make_user(admin_engine, "swap@ares.test", roles=("viewer",))
    add_factor(admin_engine, uid, status="active")
    new_secret = add_factor(admin_engine, uid, status="pending")
    with DbSession(admin_engine) as db:
        factor = db.scalar(select(MfaFactor).where(MfaFactor.status == "pending"))
        assert factor is not None
        key = crypto.parse_key(TEST_MFA_KEY)
        factor.secret_ciphertext = crypto.encrypt_secret(key, uid, "totp", new_secret)
        db.commit()
        assert mfa.confirm_enrollment(db, key, uid, pyotp.TOTP(new_secret).now(), datetime.now(UTC))
        db.commit()
    with DbSession(admin_engine) as db:
        statuses = sorted(db.scalars(select(MfaFactor.status)))
    assert statuses == ["active", "revoked"]


def test_mfa_constraints(admin_engine: Engine) -> None:
    from sqlalchemy.exc import IntegrityError

    uid = make_user(admin_engine, "cons@ares.test")
    add_factor(admin_engine, uid, status="active")
    base = (
        "INSERT INTO mfa_factors (id, user_id, type, secret_ciphertext, secret_ref, status, "
        "created_at) VALUES (gen_random_uuid(), :u, :t, '\\x00', :ref, :st, now())"
    )

    def insert(t: str = "totp", ref: str = "env:v1", st: str = "pending") -> None:
        with admin_engine.begin() as conn:
            conn.execute(text(base), {"u": uid, "t": t, "ref": ref, "st": st})

    insert()  # válido: um segundo fator pendente não conflita
    for kwargs in ({"st": "x"}, {"t": "sms"}, {"ref": "vault:1"}, {"st": "active"}):
        with pytest.raises(IntegrityError):
            insert(**kwargs)


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/api/v1/auth/mfa/confirm"),
        ("POST", "/api/v1/auth/mfa/verify"),
        ("POST", "/api/v1/auth/recovery-codes"),
        ("DELETE", "/api/v1/auth/mfa"),
        ("POST", "/api/v1/auth/recovery/confirm"),
    ],
)
def test_json_routes_reject_wrong_content_type_and_bad_json(
    client: TestClient, method: str, path: str
) -> None:
    r = client.request(method, path, content=b"x=1", headers={"Content-Type": "text/plain"})
    assert r.status_code == 400 and r.json()["code"] == "unsupported_content_type"
    r = client.request(
        method, path, content=b"{nao e json", headers={"Content-Type": "application/json"}
    )
    assert r.status_code in (400, 401)  # 400 JSON malformado; 401 se a sessão vem antes


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/api/v1/auth/mfa/enroll"),
        ("POST", "/api/v1/auth/mfa/confirm"),
        ("POST", "/api/v1/auth/mfa/verify"),
        ("POST", "/api/v1/auth/recovery/confirm"),
        ("POST", "/api/v1/auth/recovery-codes"),
        ("DELETE", "/api/v1/auth/mfa"),
    ],
)
def test_mfa_routes_reject_unknown_query(client: TestClient, method: str, path: str) -> None:
    r = client.request(method, path, params={"x": "1"}, json={})
    assert r.status_code == 400 and r.json()["code"] == "unknown_query_parameter"


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/api/v1/auth/mfa/confirm", {"code": "123456", "role": "x"}),
        ("/api/v1/auth/mfa/verify", {"code": "123456", "role": "x"}),
    ],
)
def test_mfa_routes_reject_extra_fields(
    client: TestClient, path: str, body: dict[str, str]
) -> None:
    r = client.post(path, json=body)
    assert r.status_code == 422
    assert {"field": "body.role", "type": "extra_forbidden"} in r.json()["details"]


def test_session_routes_reject_extra_fields(client: TestClient, admin_engine: Engine) -> None:
    uid = make_user(admin_engine, "xf@ares.test", roles=("viewer",))
    secret = add_factor(admin_engine, uid)
    csrf = str(login_mfa(client, admin_engine, "xf@ares.test", secret)["csrf_token"])
    h = {CSRF_HEADER: csrf}
    r = client.post("/api/v1/auth/recovery-codes", json={"password": PASSWORD, "x": 1}, headers=h)
    assert r.status_code == 422
    r = client.request(
        "DELETE",
        "/api/v1/auth/mfa",
        json={"password": PASSWORD, "code": "123456", "x": 1},
        headers=h,
    )
    assert r.status_code == 422


def test_mfa_routes_without_key_are_503(app_engine: Engine, admin_engine: Engine) -> None:
    make_user(admin_engine, "pl@ares.test", roles=("viewer",))
    app = create_app(_settings(mfa_key=None), engine=app_engine)
    with TestClient(app, base_url="https://testserver") as c:
        assert c.post("/api/v1/auth/mfa/enroll").json()["code"] == "mfa_unavailable"
        for path in ("/api/v1/auth/mfa/confirm", "/api/v1/auth/mfa/verify"):
            r = c.post(path, json={"code": "123456"})
            assert r.status_code == 503 and r.json()["code"] == "mfa_unavailable"
        csrf = str(
            c.post(
                "/api/v1/auth/login", json={"email": "pl@ares.test", "password": PASSWORD}
            ).json()["csrf_token"]
        )
        r = c.request(
            "DELETE",
            "/api/v1/auth/mfa",
            json={"password": PASSWORD, "code": "123456"},
            headers={CSRF_HEADER: csrf},
        )
        assert r.status_code == 503 and r.json()["code"] == "mfa_unavailable"


def test_disable_requires_session_and_csrf(client: TestClient, admin_engine: Engine) -> None:
    payload = {"password": PASSWORD, "code": "123456"}
    assert client.request("DELETE", "/api/v1/auth/mfa", json=payload).status_code == 401
    uid = make_user(admin_engine, "dc@ares.test", roles=("viewer",))
    login_mfa(client, admin_engine, "dc@ares.test", add_factor(admin_engine, uid))
    r = client.request("DELETE", "/api/v1/auth/mfa", json=payload)
    assert r.status_code == 403 and r.json()["code"] == "csrf_failed"


# --- achados da revisão de segurança ----------------------------------------


def _failed_count(engine: Engine, email: str) -> int:
    with DbSession(engine) as db:
        value = db.scalar(select(User.failed_login_count).where(User.email == email))
    assert value is not None
    return value


def test_mfa_failures_count_against_the_account_and_lock_it(
    client: TestClient, admin_engine: Engine
) -> None:
    """Refazer a senha não dá palpites novos de graça: 5 falhas no total travam a conta."""
    uid = make_user(admin_engine, "bf@ares.test", roles=("viewer",))
    secret = add_factor(admin_engine, uid)
    for _ in range(2):  # dois desafios, três palpites errados em cada (um a mais que o necessário)
        login_step1(client, "bf@ares.test")
        for _ in range(3):
            client.post("/api/v1/auth/mfa/verify", json={"code": "000000"})
        if _failed_count(admin_engine, "bf@ares.test") >= 5:
            break
    assert _failed_count(admin_engine, "bf@ares.test") >= 5
    with DbSession(admin_engine) as db:
        locked = db.scalar(select(User.locked_until).where(User.email == "bf@ares.test"))
    assert locked is not None and locked > datetime.now(UTC)
    # Travada: nem senha certa com código certo entra, e a resposta é a genérica.
    r = login_step1(client, "bf@ares.test")
    assert r.status_code == 401 and r.json()["code"] == "invalid_credentials"
    assert fresh_code(admin_engine, secret)  # o código certo existiria; não adianta
    locked_events = [d for d in _audit_details(admin_engine, "mfa.verify") if d.get("locked_now")]
    assert len(locked_events) == 1  # o bloqueio foi auditado uma vez


def _audit_details(engine: Engine, action: str) -> list[dict[str, object]]:
    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT details FROM audit_logs WHERE action = :a ORDER BY id"), {"a": action}
        ).all()
    return [dict(r[0]) for r in rows]


def test_correct_password_does_not_reset_mfa_failures(
    client: TestClient, admin_engine: Engine
) -> None:
    uid = make_user(admin_engine, "keepc@ares.test", roles=("viewer",))
    secret = add_factor(admin_engine, uid)
    login_step1(client, "keepc@ares.test")
    for _ in range(3):
        client.post("/api/v1/auth/mfa/verify", json={"code": "000000"})
    assert _failed_count(admin_engine, "keepc@ares.test") == 3
    login_step1(client, "keepc@ares.test")  # senha certa de novo: NÃO zera
    assert _failed_count(admin_engine, "keepc@ares.test") == 3
    r = client.post("/api/v1/auth/mfa/verify", json={"code": fresh_code(admin_engine, secret)})
    assert r.status_code == 200  # login completo: agora zera
    assert _failed_count(admin_engine, "keepc@ares.test") == 0


def test_locked_account_cannot_verify(client: TestClient, admin_engine: Engine) -> None:
    uid = make_user(admin_engine, "lv@ares.test", roles=("viewer",))
    secret = add_factor(admin_engine, uid)
    login_step1(client, "lv@ares.test")
    with DbSession(admin_engine) as db:
        db.execute(update(User).values(locked_until=datetime.now(UTC) + timedelta(minutes=5)))
        db.commit()
    r = client.post("/api/v1/auth/mfa/verify", json={"code": fresh_code(admin_engine, secret)})
    assert r.status_code == 401 and r.json()["code"] == "unauthenticated"


def test_verify_rate_limit_per_ip(app_engine: Engine, admin_engine: Engine) -> None:
    app = create_app(_settings(login_rate_limit_per_minute=2), engine=app_engine)
    with TestClient(app, base_url="https://testserver") as c:
        for _ in range(2):
            assert c.post("/api/v1/auth/mfa/verify", json={"code": "123456"}).status_code == 401
        r = c.post("/api/v1/auth/mfa/verify", json={"code": "123456"})
        assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1


def test_enroll_by_session_requires_password(client: TestClient, admin_engine: Engine) -> None:
    make_user(admin_engine, "ep@ares.test", roles=("viewer",))
    csrf = str(
        client.post(
            "/api/v1/auth/login", json={"email": "ep@ares.test", "password": PASSWORD}
        ).json()["csrf_token"]
    )
    h = {CSRF_HEADER: csrf}
    r = client.post("/api/v1/auth/mfa/enroll", headers=h)
    assert r.status_code == 422 and r.json()["code"] == "password_required"
    r = client.post("/api/v1/auth/mfa/enroll", json={"password": "errada-errada"}, headers=h)
    assert r.status_code == 401 and r.json()["code"] == "invalid_credentials"
    assert _failed_count(admin_engine, "ep@ares.test") == 1  # a falha contou na conta
    r = client.post("/api/v1/auth/mfa/enroll", json={"password": PASSWORD}, headers=h)
    assert r.status_code == 201 and r.json()["secret"]


def test_reauthentication_failures_count_for_disable_and_codes(
    client: TestClient, admin_engine: Engine
) -> None:
    uid = make_user(admin_engine, "rf@ares.test", roles=("viewer",))
    secret = add_factor(admin_engine, uid)
    csrf = str(login_mfa(client, admin_engine, "rf@ares.test", secret)["csrf_token"])
    h = {CSRF_HEADER: csrf}
    client.post("/api/v1/auth/recovery-codes", json={"password": "errada-errada"}, headers=h)
    client.request(
        "DELETE",
        "/api/v1/auth/mfa",
        json={"password": "errada-errada", "code": "000000"},
        headers=h,
    )
    assert _failed_count(admin_engine, "rf@ares.test") == 2


def test_decrypt_failure_is_503_not_500(client: TestClient, admin_engine: Engine) -> None:
    uid = make_user(admin_engine, "bad@ares.test", roles=("viewer",))
    add_factor(admin_engine, uid)
    with DbSession(admin_engine) as db:
        db.execute(update(MfaFactor).values(secret_ciphertext=b"curto"))  # < tamanho do nonce
        db.commit()
    login_step1(client, "bad@ares.test")
    r = client.post("/api/v1/auth/mfa/verify", json={"code": "123456"})
    assert r.status_code == 503 and r.json()["code"] == "mfa_unavailable"
    assert "curto" not in r.text


def test_auth_responses_are_not_cacheable(client: TestClient, admin_engine: Engine) -> None:
    uid = make_user(admin_engine, "nc@ares.test", roles=("viewer",))
    secret = add_factor(admin_engine, uid)
    r = login_step1(client, "nc@ares.test")
    assert r.headers["cache-control"] == "no-store"
    r = client.post("/api/v1/auth/mfa/verify", json={"code": fresh_code(admin_engine, secret)})
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    assert client.get("/health").headers.get("cache-control") != "no-store"


def test_enrollment_secret_not_in_repr() -> None:
    e = mfa.Enrollment(secret="SEGREDO-XYZ", otpauth_uri="otpauth://totp/x?secret=SEGREDO-XYZ")
    assert "SEGREDO-XYZ" not in repr(e)


def test_two_pending_factors_do_not_break_confirm(client: TestClient, admin_engine: Engine) -> None:
    uid = make_user(admin_engine, "pp@ares.test", roles=("viewer",))
    add_factor(admin_engine, uid, status="pending")
    newest = add_factor(admin_engine, uid, status="pending")
    key = crypto.parse_key(TEST_MFA_KEY)
    with DbSession(admin_engine) as db:
        db.execute(
            update(MfaFactor)
            .where(MfaFactor.status == "pending")
            .values(created_at=datetime.now(UTC) - timedelta(hours=1))
        )
        newest_row = db.scalar(select(MfaFactor).order_by(MfaFactor.id).limit(1))
        assert newest_row is not None
        newest_row.created_at = datetime.now(UTC)
        newest_row.secret_ciphertext = crypto.encrypt_secret(key, uid, "totp", newest)
        db.commit()
        assert mfa.confirm_enrollment(db, key, uid, pyotp.TOTP(newest).now(), datetime.now(UTC))


def test_weak_password_422_does_not_reveal_token_validity(
    client: TestClient, admin_engine: Engine
) -> None:
    make_user(admin_engine, "orc@ares.test")
    valid = cli.issue_recovery(admin_engine, "orc@ares.test")
    bodies = []
    for token in (valid, "x" * 43):
        r = client.post(
            "/api/v1/auth/recovery/confirm", json={"token": token, "new_password": "curta"}
        )
        assert r.status_code == 422
        bodies.append({k: v for k, v in r.json().items() if k != "request_id"})
    assert bodies[0] == bodies[1]


def test_recovery_failures_are_logged_not_audited(client: TestClient, admin_engine: Engine) -> None:
    for _ in range(3):
        client.post(
            "/api/v1/auth/recovery/confirm", json={"token": "x" * 43, "new_password": NEW_PASSWORD}
        )
    assert audit_actions(admin_engine) == []  # nenhuma linha permanente por tentativa inválida


def test_mfa_verify_revokes_previous_session_cookie(
    client: TestClient, admin_engine: Engine
) -> None:
    """Fixação de sessão também vale pelo caminho do MFA."""
    make_user(admin_engine, "fx-plain@ares.test", roles=("viewer",))
    client.post("/api/v1/auth/login", json={"email": "fx-plain@ares.test", "password": PASSWORD})
    old = client.cookies.get(SESSION_COOKIE)
    assert old and client.get("/api/v1/me").status_code == 200

    uid = make_user(admin_engine, "fx-mfa@ares.test", roles=("viewer",))
    secret = add_factor(admin_engine, uid)
    login_mfa(client, admin_engine, "fx-mfa@ares.test", secret)
    new = client.cookies.get(SESSION_COOKIE)
    assert new and new != old

    client.cookies.clear()
    client.cookies.set(SESSION_COOKIE, old)
    assert client.get("/api/v1/me").status_code == 401

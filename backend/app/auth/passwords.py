"""Hash e política de senha (CLAUDE.md, seção 9.1; ADR 0003).

- Argon2id via argon2-cffi. Parâmetros calibrados nesta máquina em
  26/11/2026: t=10, m=64 MiB, p=4, cerca de 125 ms por verificação
  (docs/ENVIRONMENT.md). Hash antigo é refeito no próximo login.
- No máximo ``MAX_CONCURRENT_HASHES`` operações ao mesmo tempo (teto de
  memória; ver ADR 0003).
- Política: 12 a 128 caracteres, sem regra de composição (NIST SP 800-63B),
  diferente do e-mail.
"""

import threading

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

MIN_LENGTH = 12
MAX_LENGTH = 128

TIME_COST = 10
MEMORY_COST_KIB = 64 * 1024
PARALLELISM = 4

# Teto de memória: no máximo N operações Argon2 ao mesmo tempo
# (4 x 64 MiB = 256 MiB). Acima disso, quem espera mais que o timeout
# recebe HasherBusy (a rota responde 503 com Retry-After).
MAX_CONCURRENT_HASHES = 4
ACQUIRE_TIMEOUT_SECONDS = 5.0
_DUMMY_PASSWORD = "ares-dummy-password-for-timing"


class HasherBusy(Exception):
    pass


def _build(time_cost: int, memory_cost_kib: int, parallelism: int) -> tuple[PasswordHasher, str]:
    hasher = PasswordHasher(
        time_cost=time_cost, memory_cost=memory_cost_kib, parallelism=parallelism
    )
    # Hash fictício gerado já na inicialização: a primeira conta inexistente
    # não custa mais que as outras.
    return hasher, hasher.hash(_DUMMY_PASSWORD)


_hasher, _dummy_hash = _build(TIME_COST, MEMORY_COST_KIB, PARALLELISM)
_slots = threading.BoundedSemaphore(MAX_CONCURRENT_HASHES)


def configure_for_tests(
    time_cost: int = 1,
    memory_cost_kib: int = 8,
    parallelism: int = 1,
    max_concurrent: int = MAX_CONCURRENT_HASHES,
    acquire_timeout: float = ACQUIRE_TIMEOUT_SECONDS,
) -> None:
    """Parâmetros baratos só para a suíte de testes. Nunca chamar na aplicação."""
    global _hasher, _dummy_hash, _slots, ACQUIRE_TIMEOUT_SECONDS
    _hasher, _dummy_hash = _build(time_cost, memory_cost_kib, parallelism)
    _slots = threading.BoundedSemaphore(max_concurrent)
    ACQUIRE_TIMEOUT_SECONDS = acquire_timeout


class _Slot:
    def __enter__(self) -> None:
        if not _slots.acquire(timeout=ACQUIRE_TIMEOUT_SECONDS):
            raise HasherBusy
        self._sem = _slots

    def __exit__(self, *_: object) -> None:
        self._sem.release()


def policy_violation(password: str, email: str) -> str | None:
    """Devolve o código do erro de política, ou ``None`` se a senha é aceita."""
    if len(password) < MIN_LENGTH:
        return "password_too_short"
    if len(password) > MAX_LENGTH:
        return "password_too_long"
    if password.strip().lower() == email.strip().lower():
        return "password_equals_email"
    return None


def hash_password(password: str) -> str:
    with _Slot():
        return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    with _Slot():
        try:
            return _hasher.verify(password_hash, password)
        except VerificationError, InvalidHashError:
            return False


def verify_dummy(password: str) -> None:
    """Gasta o mesmo tempo de uma verificação real (conta inexistente,
    desativada ou bloqueada), para o tempo de resposta não revelar a conta."""
    verify_password(_dummy_hash, password)


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)

"""Cifra do segredo TOTP em repouso (ADR 0005).

AES-GCM (``cryptography``) com chave de 32 bytes vinda de ``ARES_MFA_KEY``
(base64, fora do Git). O formato do blob é ``nonce(12) || texto cifrado+tag``.
Os dados autenticados (AAD) ligam o blob ao usuário e ao tipo de fator: um
blob copiado para outra linha não decifra.

``KEY_REF`` identifica a versão da chave e é gravado em ``secret_ref``; é o
que permitirá rotacionar a chave (ADR 0005, "Em aberto").
"""

import base64
import binascii
import os
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_REF = "env:v1"
NONCE_BYTES = 12
KEY_BYTES = 32


class MfaCryptoError(Exception):
    """Chave ausente/inválida ou blob que não decifra. Sem detalhes na mensagem."""


def parse_key(raw: str) -> bytes:
    try:
        key = base64.b64decode(raw, validate=True)
    except binascii.Error, ValueError:
        raise MfaCryptoError("ARES_MFA_KEY não é base64 válido.") from None
    if len(key) != KEY_BYTES:
        raise MfaCryptoError("ARES_MFA_KEY deve ter 32 bytes (base64).")
    return key


def generate_key() -> str:
    """Chave nova, para colocar em ARES_MFA_KEY."""
    return base64.b64encode(os.urandom(KEY_BYTES)).decode("ascii")


def _aad(user_id: uuid.UUID, factor_type: str) -> bytes:
    return f"ares-mfa:{factor_type}:{user_id}".encode()


def encrypt_secret(key: bytes, user_id: uuid.UUID, factor_type: str, secret: str) -> bytes:
    nonce = os.urandom(NONCE_BYTES)
    return nonce + AESGCM(key).encrypt(nonce, secret.encode("ascii"), _aad(user_id, factor_type))


def decrypt_secret(key: bytes, user_id: uuid.UUID, factor_type: str, blob: bytes) -> str:
    try:
        plain = AESGCM(key).decrypt(
            blob[:NONCE_BYTES], blob[NONCE_BYTES:], _aad(user_id, factor_type)
        )
    except InvalidTag, ValueError:  # ValueError: nonce/blob curto demais
        raise MfaCryptoError("Segredo MFA não pôde ser decifrado.") from None
    return plain.decode("ascii")

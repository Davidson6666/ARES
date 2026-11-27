"""Camada de persistência: engine e sessão SQLAlchemy (acesso síncrono, ADR 0002)."""

from collections.abc import Iterator

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

CONNECT_TIMEOUT_SECONDS = 2


def build_engine(url: str) -> Engine:
    return create_engine(
        url,
        pool_pre_ping=True,
        # Erros do banco não carregam valores dos parâmetros (e-mail, senha
        # digitada no campo errado etc.) para exceções e logs.
        hide_parameters=True,
        connect_args={"connect_timeout": CONNECT_TIMEOUT_SECONDS},
    )


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def iter_session(factory: sessionmaker[Session]) -> Iterator[Session]:
    with factory() as session:
        yield session


def database_is_ready(engine: Engine | None) -> bool:
    """``True`` se o banco responde a ``SELECT 1``. Nunca propaga o erro."""
    if engine is None:
        return False
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except SQLAlchemyError:
        return False
    return True

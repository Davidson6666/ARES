"""Linha de comando do agente: ``enroll``, ``run`` e ``status`` (ADR 0007).

Códigos de saída: 0 ok; 2 credencial recusada pelo servidor; 3 erro de configuração,
cofre ou permissão (mensagem em texto, sem segredo).
"""

import argparse
import getpass
import json
import signal
import socket
import sqlite3
import sys
import threading
from collections.abc import Sequence

from ares_agent import client as api
from ares_agent import collector, credentials, log
from ares_agent.config import ConfigError, default_home, load_config, write_initial_config
from ares_agent.mapping import clean
from ares_agent.runner import CredentialRejected, Runner
from ares_agent.store import Store

EXIT_OK = 0
EXIT_REJECTED = 2
EXIT_ERROR = 3


def read_secret(prompt: str) -> str:
    """Lê o token sem eco no terminal ou, sem terminal, da primeira linha do stdin.

    Nunca por argumento de linha de comando (iria para o histórico do shell).
    """
    value = getpass.getpass(prompt) if sys.stdin.isatty() else sys.stdin.readline()
    return value.strip()


def _enroll(args: argparse.Namespace) -> int:
    home = default_home()
    cfg = write_initial_config(home, args.server)
    try:
        existing = credentials.load()
    except credentials.CredentialStoreError:
        existing = None
    if existing is not None and not args.force:
        print("Este usuário já tem um agente enrolado. Use --force para enrolar de novo.")
        return EXIT_ERROR
    token = read_secret("Token de enrolamento: ")
    if not token:
        print("Token vazio.")
        return EXIT_ERROR
    http = api.build_http(cfg.server_url, cfg.ca_file)
    try:
        enrolled = api.ServerClient(http).enroll(token, clean(socket.gethostname()) or "host")
    except api.EnrollmentError as exc:
        print(f"Enrolamento recusado: {exc}")
        return EXIT_ERROR
    finally:
        http.close()
    # O token de uso único já foi gasto: se algo falhar daqui em diante, o agente existe
    # ativo no servidor e a credencial só existe nesta resposta.
    try:
        credentials.save(enrolled.credential)
        store = Store(cfg.store_path, cfg.queue_max_events, cfg.queue_max_bytes)
        try:
            discarded = store.reset_for_new_enrollment() if args.force else 0
            store.put("agent_id", enrolled.agent_id)
            store.put("module", enrolled.module)
        finally:
            store.close()
    except credentials.CredentialStoreError, OSError, sqlite3.Error:
        print(
            f"O servidor ativou o agente {enrolled.agent_id}, mas a credencial não pôde ser "
            "guardada neste computador. Revogue esse agente no Core (POST /agents/{id}/revoke) "
            "e gere um novo token de enrolamento."
        )
        return EXIT_ERROR
    if discarded:
        print(f"Aviso: {discarded} evento(s) da fila do agente anterior foram descartados.")
    print(f"Enrolado. agent_id={enrolled.agent_id}")
    return EXIT_OK


def _run(args: argparse.Namespace) -> int:
    cfg = load_config()
    logger = log.setup(cfg.log_path)
    credential = credentials.load()
    agent_id = credentials.parse_agent_id(credential)
    collector.check_access()
    store = Store(cfg.store_path, cfg.queue_max_events, cfg.queue_max_bytes)
    module = store.get("module")
    if module is None:
        print("Estado local sem o módulo do agente. Rode `enroll --force`.")
        return EXIT_ERROR
    http = api.build_http(cfg.server_url, cfg.ca_file)
    stop = threading.Event()
    for name in ("SIGINT", "SIGBREAK", "SIGTERM"):
        if (sig := getattr(signal, name, None)) is not None:
            signal.signal(sig, lambda *_: stop.set())
    runner = Runner(cfg, store, api.ServerClient(http, credential), agent_id, module, logger)
    try:
        runner.run(stop)
    except CredentialRejected:
        print("Credencial inválida ou revogada. Peça um novo token de enrolamento.")
        return EXIT_REJECTED
    finally:
        http.close()
        store.close()
    return EXIT_OK


def _status(args: argparse.Namespace) -> int:
    cfg = load_config()
    store = Store(cfg.store_path, cfg.queue_max_events, cfg.queue_max_bytes)
    try:
        report = {
            "server_url": cfg.server_url,
            "agent_id": store.get("agent_id"),
            "module": store.get("module"),
            "collected_record_id": store.get("collected_record_id"),
            "log_latest_record_id": store.get("log_latest_record_id"),
            "collection_lag": _lag(store),
            "last_contact_at": store.get("last_contact_at"),
            "last_error": store.get("last_error") or None,
            **store.stats(),
        }
    finally:
        store.close()
    print(json.dumps(report, indent=2))
    return EXIT_OK


def _lag(store: Store) -> int | None:
    """Quantos registros o log tem além do marcador (atraso da coleta)."""
    latest, mark = store.get("log_latest_record_id"), store.get("collected_record_id")
    if latest is None or mark is None:
        return None
    return max(int(latest) - int(mark), 0)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ares-agent", description="Agente de telemetria ARES.")
    sub = parser.add_subparsers(dest="command", required=True)
    enroll = sub.add_parser("enroll", help="Troca o token de enrolamento pela credencial.")
    enroll.add_argument("--server", required=True, help="https://servidor (http só em loopback)")
    enroll.add_argument("--force", action="store_true", help="Enrola de novo, substituindo.")
    enroll.set_defaults(func=_enroll)
    sub.add_parser("run", help="Coleta e envia eventos até Ctrl+C.").set_defaults(func=_run)
    sub.add_parser("status", help="Estado local, sem segredos.").set_defaults(func=_status)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (ConfigError, credentials.CredentialStoreError, collector.CollectorError) as exc:
        print(f"Erro: {exc}")
        return EXIT_ERROR

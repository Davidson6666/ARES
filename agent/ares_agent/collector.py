"""Coleta do Security log do Windows por ``wevtutil`` (ADR 0007).

Sem shell, com caminho absoluto e argumentos fixos: nenhum valor vindo de evento
chega à linha de comando. A saída é XML em UTF-16 (``/uni:true``); o conteúdo é
**não confiável** (nomes de usuário e estações vêm de terceiros) e nunca sai do
host cru: ``mapping`` escolhe os campos.
"""

import os
import re
import subprocess
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ares_agent import ids

CHANNEL = "Security"
EVENT_IDS = (4624, 4625, 4648, 4672, 4720, 4732)
MAX_OUTPUT_BYTES = 32 * 1024 * 1024
TIMEOUT_SECONDS = 30
_ACCESS_DENIED = 5
_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
_XML_DECL = re.compile(r"^\s*<\?xml[^>]*\?>")
# Caracteres que o XML 1.0 não admite, nem como referência numérica. O nome de usuário de
# um logon falho vem de quem tenta entrar: não pode travar a coleta.
_INVALID_RAW = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]")
_CHAR_REF = re.compile(r"&#(x[0-9a-fA-F]{1,8}|[0-9]{1,10});")
_RECORD_ID = re.compile(r"<EventRecordID>\s*(\d+)\s*</EventRecordID>")
CREATE_NO_WINDOW = 0x08000000


class CollectorError(RuntimeError):
    """Falha ao ler o log; a mensagem é segura para exibir e registrar."""


class MalformedOutput(CollectorError):
    """A saída do wevtutil não é XML aceitável (o runner isola o evento problemático)."""


class AccessDenied(CollectorError):
    """Sem permissão para ler o Security log (grupo ``Event Log Readers``)."""


@dataclass(frozen=True)
class RawEvent:
    windows_event_id: int
    record_id: int
    system_time: str
    fields: dict[str, str]


Runner = Callable[[list[str]], bytes]


def windows_directory() -> Path:
    """Diretório do Windows pela API do sistema (não confia só em variável de ambiente)."""
    try:
        import ctypes

        buffer = ctypes.create_unicode_buffer(260)
        if ctypes.windll.kernel32.GetSystemWindowsDirectoryW(buffer, 260):  # type: ignore[attr-defined,unused-ignore]
            return Path(buffer.value)
    except AttributeError, OSError:
        pass
    return Path(os.environ.get("SystemRoot", r"C:\Windows"))


def wevtutil_path() -> Path:
    return windows_directory() / "System32" / "wevtutil.exe"


def run_wevtutil(args: list[str]) -> bytes:
    try:
        done = subprocess.run(
            [str(wevtutil_path()), *args],
            capture_output=True,
            timeout=TIMEOUT_SECONDS,
            stdin=subprocess.DEVNULL,
            shell=False,
            creationflags=CREATE_NO_WINDOW,
            check=False,
        )
    except OSError, subprocess.TimeoutExpired:
        raise CollectorError("Não foi possível executar o wevtutil.") from None
    if done.returncode == _ACCESS_DENIED:
        raise AccessDenied(
            "Sem acesso ao Security log. Adicione o usuário ao grupo "
            "'Event Log Readers' (e faça novo logon) ou rode em terminal elevado."
        )
    if done.returncode != 0:
        raise CollectorError(f"O wevtutil falhou (código {done.returncode}).")
    if len(done.stdout) > MAX_OUTPUT_BYTES:
        raise CollectorError("Saída do wevtutil acima do limite.")
    return done.stdout


def _decode(raw: bytes) -> str:
    if not raw.strip():
        return ""
    # Com BOM (/uni:true). ``replace``: um substituto solto num nome de usuário não pode
    # travar a coleta.
    return raw.decode("utf-16", errors="replace")


def xpath_after(record_id: int) -> str:
    ids = " or ".join(f"EventID={i}" for i in EVENT_IDS)
    return f"*[System[({ids}) and EventRecordID>{int(record_id)}]]"


def query(after_record_id: int, limit: int, run: Runner = run_wevtutil) -> str:
    """Eventos suportados com ``EventRecordID`` maior que o marcador, do mais antigo ao mais novo."""
    out = run(
        [
            "qe",
            CHANNEL,
            f"/q:{xpath_after(after_record_id)}",
            "/f:xml",
            "/uni:true",
            "/rd:false",
            f"/c:{int(limit)}",
        ]
    )
    return _decode(out)


def latest_record_id(run: Runner = run_wevtutil) -> int:
    """Maior ``EventRecordID`` do log (0 se vazio). Ponto de partida: só eventos novos."""
    text = _decode(run(["qe", CHANNEL, "/f:xml", "/uni:true", "/rd:true", "/c:1"]))
    events = parse_events(text, only_supported=False)
    return max((e.record_id for e in events), default=0)


def _valid_char(code: int) -> bool:
    return (
        code in (9, 10, 13)
        or 0x20 <= code <= 0xD7FF
        or 0xE000 <= code <= 0xFFFD
        or 0x10000 <= code <= 0x10FFFF
    )


def _ref(match: re.Match[str]) -> str:
    body = match.group(1)
    code = int(body[1:], 16) if body[0] == "x" else int(body)
    return match.group(0) if _valid_char(code) else "\ufffd"


def _sanitize(text: str) -> str:
    return _CHAR_REF.sub(_ref, _INVALID_RAW.sub("\ufffd", text))


def first_record_id(text: str) -> int | None:
    """Primeiro ``EventRecordID`` do texto, mesmo que o XML esteja quebrado."""
    match = _RECORD_ID.search(text)
    return int(match.group(1)) if match else None


def parse_events(text: str, *, only_supported: bool = True) -> list[RawEvent]:
    if not text.strip():
        return []
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        raise MalformedOutput("Saída do wevtutil com declaração DTD; descartada.")
    text = _XML_DECL.sub("", _sanitize(text), count=1)
    try:
        root = ET.fromstring(f"<Events>{text}</Events>")
    except ET.ParseError:
        raise MalformedOutput("Saída do wevtutil não é XML válido.") from None
    events: list[RawEvent] = []
    for node in root.findall(f"{_NS}Event"):
        raw = _one(node)
        if raw is not None and (not only_supported or raw.windows_event_id in EVENT_IDS):
            events.append(raw)
    return events


def _one(node: ET.Element) -> RawEvent | None:
    system = node.find(f"{_NS}System")
    if system is None:
        return None
    event_id = (system.findtext(f"{_NS}EventID") or "").strip()
    record_id = (system.findtext(f"{_NS}EventRecordID") or "").strip()
    created = system.find(f"{_NS}TimeCreated")
    if not (ids.is_ascii_number(event_id) and ids.is_ascii_number(record_id)) or created is None:
        return None
    fields = {
        name: (data.text or "")
        for data in node.findall(f"{_NS}EventData/{_NS}Data")
        if (name := data.get("Name"))
    }
    return RawEvent(int(event_id), int(record_id), created.get("SystemTime", ""), fields)


def check_access(run: Runner = run_wevtutil) -> None:
    """Falha com ``AccessDenied`` se o usuário não lê o Security log."""
    run(["qe", CHANNEL, "/f:xml", "/uni:true", "/c:1"])

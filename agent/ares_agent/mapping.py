"""Mapeamento de eventos do Windows para o envelope v1 (ADR 0007).

Lista fixa de campos por ``EventID``: o que não está aqui não sai do host. Nunca
se coleta linha de comando, conteúdo de arquivo, senha nem a mensagem em texto
livre. Valores são texto não confiável: caracteres de controle viram U+FFFD e o
tamanho é limitado.
"""

import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from ares_agent import ids
from ares_agent.collector import CHANNEL, RawEvent

# Namespace fixo do ``event_id`` determinístico (UUIDv5). Não é segredo.
NAMESPACE = uuid.UUID("5b0f5c0e-3f8c-4d6e-9a41-0c6f1d9a7e12")
SCHEMA_VERSION = 1
CLASSIFICATION = "personal"
MAX_VALUE = 256
_TIME = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z$")


@dataclass(frozen=True)
class Spec:
    event_type: str
    fields: dict[str, str]  # nome no Windows -> nome em `data`
    ints: frozenset[str] = frozenset()  # nomes em `data` que são inteiros


SPECS: dict[int, Spec] = {
    4624: Spec(
        "authentication.success",
        {
            "TargetUserName": "user",
            "TargetDomainName": "domain",
            "LogonType": "logon_type",
            "WorkstationName": "workstation",
            "IpAddress": "source_address",
            "ProcessName": "process",
        },
        frozenset({"logon_type"}),
    ),
    4625: Spec(
        "authentication.failure",
        {
            "TargetUserName": "user",
            "TargetDomainName": "domain",
            "LogonType": "logon_type",
            "WorkstationName": "workstation",
            "IpAddress": "source_address",
            "ProcessName": "process",
            "Status": "status",
            "SubStatus": "sub_status",
        },
        frozenset({"logon_type"}),
    ),
    4648: Spec(
        "authentication.explicit_credentials",
        {
            "SubjectUserName": "source_user",
            "SubjectDomainName": "source_domain",
            "TargetUserName": "target_user",
            "TargetDomainName": "target_domain",
            "ProcessName": "process",
        },
    ),
    4672: Spec(
        "privilege.special_assigned",
        {"SubjectUserName": "user", "SubjectDomainName": "domain"},
    ),
    4720: Spec(
        "account.created",
        {
            "TargetUserName": "account",
            "TargetDomainName": "account_domain",
            "SubjectUserName": "actor_user",
            "SubjectDomainName": "actor_domain",
        },
    ),
    4732: Spec(
        "group.member_added",
        {
            "MemberName": "member",
            "MemberSid": "member_sid",
            "TargetUserName": "group",
            "SubjectUserName": "actor_user",
            "SubjectDomainName": "actor_domain",
        },
    ),
}


def clean(value: str) -> str | None:
    """Texto seguro: sem controle, com limite; ``-`` e vazio (convenção do Windows) viram nulo."""
    text = "".join("�" if ord(c) < 32 or ord(c) == 127 else c for c in value).strip()
    if text in {"", "-"}:
        return None
    return text[:MAX_VALUE]


def occurred_at(system_time: str) -> str | None:
    """``2026-11-27T19:34:23.2558926Z`` -> RFC 3339 com no máximo microssegundos."""
    match = _TIME.fullmatch(system_time)
    if match is None:
        return None
    base, frac = match.group(1), (match.group(2) or "")[:6]
    try:
        datetime.strptime(base, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None
    return f"{base}.{frac}Z" if frac else f"{base}Z"


def make_event_id(agent_id: str, record_id: int, epoch: int = 0) -> str:
    """Determinístico: reler o mesmo registro dá o mesmo ``event_id`` (o servidor deduplica).

    ``epoch`` conta quantas vezes o Security log foi reiniciado (limpo): depois disso a
    numeração de ``EventRecordID`` recomeça e os ids antigos não podem ser reusados.
    """
    suffix = f"|epoch{epoch}" if epoch else ""
    return str(uuid.uuid5(NAMESPACE, f"{agent_id}|{CHANNEL}{suffix}|{record_id}"))


# Prioridade na fila local: logons (4624, 4625) são volumosos e um atacante os gera à
# vontade; conta criada, grupo e privilégio sobrevivem ao descarte por estouro.
LOW_PRIORITY_IDS = frozenset({4624, 4625})
OVERFLOW_PRIORITY = 9


def priority(windows_event_id: int) -> int:
    return 0 if windows_event_id in LOW_PRIORITY_IDS else 1


def to_envelope(raw: RawEvent, agent_id: str, module: str, epoch: int = 0) -> dict[str, Any] | None:
    """Envelope v1 do evento, ou ``None`` se o tipo não é suportado ou está malformado."""
    spec = SPECS.get(raw.windows_event_id)
    when = occurred_at(raw.system_time)
    if spec is None or when is None:
        return None
    data: dict[str, Any] = {
        "channel": CHANNEL,
        "windows_event_id": raw.windows_event_id,
        "record_id": raw.record_id,
    }
    for source, target in spec.fields.items():
        value = clean(raw.fields.get(source, ""))
        if target in spec.ints:
            data[target] = (
                int(value) if value is not None and ids.is_ascii_number(value, 9) else None
            )
        else:
            data[target] = value
    return {
        "event_id": make_event_id(agent_id, raw.record_id, epoch),
        "event_type": spec.event_type,
        "schema_version": SCHEMA_VERSION,
        "occurred_at": when,
        "source": {"module": module, "instance_id": agent_id},
        "data_classification": CLASSIFICATION,
        "data": data,
    }


def overflow_envelope(
    agent_id: str, module: str, dropped: int, total: int, now: datetime
) -> dict[str, Any]:
    """Evento ``agent.queue_overflow``: avisa que a fila local descartou eventos."""
    return {
        # Com o instante: se o estado local for perdido, o total recomeça e o id não repete.
        "event_id": str(uuid.uuid5(NAMESPACE, f"{agent_id}|overflow|{total}|{now.isoformat()}")),
        "event_type": "agent.queue_overflow",
        "schema_version": SCHEMA_VERSION,
        "occurred_at": now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "source": {"module": module, "instance_id": agent_id},
        "data_classification": "internal",
        "data": {"dropped": dropped, "dropped_total": total},
    }


def log_reset_envelope(
    agent_id: str, module: str, epoch: int, previous_record_id: int, now: datetime
) -> dict[str, Any]:
    """Evento ``agent.log_reset``: o Security log foi limpo (a numeração recomeçou).

    Quem limpa o log costuma querer apagar rastro: o servidor precisa saber.
    """
    return {
        "event_id": str(uuid.uuid5(NAMESPACE, f"{agent_id}|logreset|{epoch}")),
        "event_type": "agent.log_reset",
        "schema_version": SCHEMA_VERSION,
        "occurred_at": now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "source": {"module": module, "instance_id": agent_id},
        "data_classification": "internal",
        "data": {"epoch": epoch, "previous_record_id": previous_record_id},
    }

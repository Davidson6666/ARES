import json
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from ares_agent import collector, mapping
from tests.helpers import AGENT_ID, event_xml, logon_failure


def envelope(xml: str) -> dict[str, Any]:
    (raw,) = collector.parse_events(xml)
    result = mapping.to_envelope(raw, AGENT_ID, "endpoint")
    assert result is not None
    return result


def test_failed_logon_maps_only_whitelisted_fields() -> None:
    env = envelope(logon_failure(77))
    assert env["event_type"] == "authentication.failure"
    assert env["schema_version"] == 1
    assert env["data_classification"] == "personal"
    assert env["source"] == {"module": "endpoint", "instance_id": AGENT_ID}
    assert env["occurred_at"] == "2026-11-27T19:34:23.255892Z"
    assert env["data"] == {
        "channel": "Security",
        "windows_event_id": 4625,
        "record_id": 77,
        "user": "maria",
        "domain": "LAB",
        "logon_type": 3,
        "workstation": "PC-01",
        "source_address": "10.0.0.5",
        "process": None,  # "-" é "sem valor" no Windows
        "status": "0xc000006d",
        "sub_status": "0xc000006a",
    }
    # Sem campo de topo extra: o servidor rejeita campo desconhecido, e nunca se envia observed_at.
    assert set(env) == {
        "event_id",
        "event_type",
        "schema_version",
        "occurred_at",
        "source",
        "data_classification",
        "data",
    }
    dumped = json.dumps(env)
    assert "hunter2" not in dumped and "powershell" not in dumped
    assert "CommandLine" not in dumped and "Password" not in dumped


@pytest.mark.parametrize(
    ("windows_id", "event_type", "fields", "expected"),
    [
        (
            4624,
            "authentication.success",
            {"TargetUserName": "ana", "LogonType": "2", "IpAddress": "::1"},
            {"user": "ana", "logon_type": 2, "source_address": "::1"},
        ),
        (
            4648,
            "authentication.explicit_credentials",
            {"SubjectUserName": "a", "TargetUserName": "b", "ProcessName": "C:\\x.exe"},
            {"source_user": "a", "target_user": "b", "process": "C:\\x.exe"},
        ),
        (
            4672,
            "privilege.special_assigned",
            {"SubjectUserName": "adm", "SubjectDomainName": "LAB", "PrivilegeList": "SeDebug"},
            {"user": "adm", "domain": "LAB"},
        ),
        (
            4720,
            "account.created",
            {"TargetUserName": "novo", "SubjectUserName": "adm"},
            {"account": "novo", "actor_user": "adm"},
        ),
        (
            4732,
            "group.member_added",
            {"MemberName": "CN=x", "MemberSid": "S-1-5-21-1", "TargetUserName": "Administrators"},
            {"member": "CN=x", "group": "Administrators"},
        ),
    ],
)
def test_each_supported_event_id(
    windows_id: int, event_type: str, fields: dict[str, str], expected: dict[str, object]
) -> None:
    env = envelope(event_xml(windows_id, 5, fields))
    assert env["event_type"] == event_type
    data = env["data"]
    assert {k: data[k] for k in expected} == expected
    assert "PrivilegeList" not in data
    assert "member_sid" not in data and "MemberSid" not in data  # minimização (ADR 0007, item 10)


def test_values_are_sanitized_and_bounded() -> None:
    xml = event_xml(4625, 1, {"TargetUserName": "a\nb\x01c\r", "WorkstationName": "x" * 1000})
    data = envelope(xml)["data"]
    assert data["user"] == "a\ufffdb\ufffdc\ufffd"  # sem quebra de linha nem controle
    assert len(data["workstation"]) == mapping.MAX_VALUE


def test_logon_type_must_be_digits() -> None:
    data = envelope(event_xml(4624, 1, {"LogonType": "3; drop table"}))["data"]
    assert data["logon_type"] is None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2026-11-27T19:34:23Z", "2026-11-27T19:34:23Z"),
        ("2026-11-27T19:34:23.1Z", "2026-11-27T19:34:23.1Z"),
        ("2026-11-27T19:34:23.2558926Z", "2026-11-27T19:34:23.255892Z"),
        ("2026-13-27T19:34:23Z", None),
        ("2026-11-27 19:34:23Z", None),
        ("2026-11-27T19:34:23+00:00", None),
        ("", None),
    ],
)
def test_occurred_at_normalization(raw: str, expected: str | None) -> None:
    assert mapping.occurred_at(raw) == expected


def test_malformed_time_or_unsupported_type_yields_none() -> None:
    bad = collector.RawEvent(4625, 1, "ontem", {})
    assert mapping.to_envelope(bad, AGENT_ID, "endpoint") is None
    other = collector.RawEvent(4688, 1, "2026-11-27T19:34:23Z", {})
    assert mapping.to_envelope(other, AGENT_ID, "endpoint") is None


def test_event_id_is_deterministic_and_per_agent() -> None:
    a = mapping.make_event_id(AGENT_ID, 77)
    assert a == mapping.make_event_id(AGENT_ID, 77)
    assert a != mapping.make_event_id(AGENT_ID, 78)
    assert a != mapping.make_event_id(str(uuid.uuid4()), 77)
    assert uuid.UUID(a).version == 5
    assert envelope(logon_failure(77))["event_id"] == a  # releitura = mesmo evento


def test_overflow_event() -> None:
    now = datetime(2026, 11, 27, 20, 0, 0, tzinfo=UTC)
    env = mapping.overflow_envelope(AGENT_ID, "endpoint", 5, 12, now)
    assert env["event_type"] == "agent.queue_overflow"
    assert env["data"] == {"dropped": 5, "dropped_total": 12}
    assert env["occurred_at"] == "2026-11-27T20:00:00.000000Z"
    assert env["data_classification"] == "internal"

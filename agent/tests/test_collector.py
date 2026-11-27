import subprocess
from pathlib import Path
from typing import Any

import pytest

from ares_agent import collector
from ares_agent.collector import AccessDenied, CollectorError
from tests.helpers import event_xml, logon_failure


def utf16(text: str) -> bytes:
    return b"\xff\xfe" + text.encode("utf-16-le")


def test_parse_concatenated_events_in_wevtutil_shape() -> None:
    text = logon_failure(10) + event_xml(4672, 11, {"SubjectUserName": "adm"}) + logon_failure(12)
    events = collector.parse_events(text)
    assert [e.record_id for e in events] == [10, 11, 12]
    assert [e.windows_event_id for e in events] == [4625, 4672, 4625]
    assert events[0].fields["TargetUserName"] == "maria"
    assert events[0].system_time == "2026-11-27T19:34:23.2558926Z"


def test_unsupported_ids_are_skipped_but_visible_when_asked() -> None:
    text = event_xml(4688, 5, {"NewProcessName": "x"})
    assert collector.parse_events(text) == []
    assert [e.record_id for e in collector.parse_events(text, only_supported=False)] == [5]


def test_empty_output_and_xml_declaration() -> None:
    assert collector.parse_events("") == []
    assert collector.parse_events("  \r\n") == []
    with_decl = '<?xml version="1.0" encoding="UTF-16"?>' + logon_failure(1)
    assert len(collector.parse_events(with_decl)) == 1


@pytest.mark.parametrize(
    "text",
    [
        '<!DOCTYPE x [<!ENTITY a "aaaa">]><Event/>',
        "<!ENTITY a 'b'>",
        "<Event><System>",  # XML quebrado
        "<<<",
        "</Events><Events>",  # tentativa de sair do envelope
    ],
)
def test_hostile_or_broken_output_is_refused(text: str) -> None:
    with pytest.raises(collector.MalformedOutput):
        collector.parse_events(text)


@pytest.mark.parametrize("bad", ["\x01", "\x00", "&#x1;", "&#0;", "&#xD800;", "&#1114112;"])
def test_chars_invalid_in_xml_do_not_break_collection(bad: str) -> None:
    # O nome de usuário de um logon falho é de quem tenta entrar.
    xml = logon_failure(9).replace("maria", f"ma{bad}ria")
    (event,) = collector.parse_events(xml)
    assert event.record_id == 9
    assert "�" in event.fields["TargetUserName"]


def test_valid_char_references_survive() -> None:
    (event,) = collector.parse_events(logon_failure(9).replace("maria", "ma&#x41;&#9;ria"))
    assert event.fields["TargetUserName"] == "maA\tria"


def test_first_record_id_works_on_broken_xml() -> None:
    assert collector.first_record_id("<Event><EventRecordID>77</EventRecordID><oops") == 77
    assert collector.first_record_id("nada") is None


def test_event_without_ids_or_time_is_ignored() -> None:
    bad = (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
        "<EventID>4625</EventID></System></Event>"
    )
    assert [e.record_id for e in collector.parse_events(bad + logon_failure(7))] == [7]


def test_data_without_name_and_markup_in_values() -> None:
    xml = event_xml(4625, 3, {"TargetUserName": "<script>alert(1)</script>"})
    xml = xml.replace("</EventData>", "<Data>sem nome</Data></EventData>")
    (event,) = collector.parse_events(xml)
    assert event.fields == {"TargetUserName": "<script>alert(1)</script>"}


def test_query_uses_fixed_arguments_and_decodes_utf16() -> None:
    seen: list[list[str]] = []

    def fake(args: list[str]) -> bytes:
        seen.append(args)
        return utf16(logon_failure(2, "José"))

    text = collector.query(41, 200, run=fake)
    (args,) = seen
    assert args[:2] == ["qe", "Security"]
    assert {"/f:xml", "/uni:true", "/rd:false", "/c:200"} <= set(args)
    xpath = next(a for a in args if a.startswith("/q:"))
    assert "EventRecordID>41" in xpath
    assert all(f"EventID={i}" in xpath for i in (4624, 4625, 4648, 4672, 4720, 4732))
    assert collector.parse_events(text)[0].fields["TargetUserName"] == "José"


def test_non_integer_marker_cannot_inject_into_the_query() -> None:
    captured: list[list[str]] = []

    def spy(args: list[str]) -> bytes:
        captured.append(args)
        return b""

    with pytest.raises((TypeError, ValueError)):
        collector.query("1] or 1=1 or [", 10, run=spy)  # type: ignore[arg-type]
    assert captured == []


def test_latest_record_id() -> None:
    assert collector.latest_record_id(run=lambda a: utf16(event_xml(4688, 99))) == 99
    assert collector.latest_record_id(run=lambda a: b"") == 0


def test_lone_surrogate_in_utf16_output_does_not_break_decoding() -> None:
    # 0xD800 solto (UTF-16 inválido) num nome de usuário.
    broken = utf16(logon_failure(2, "ma?ria")).replace("?".encode("utf-16-le"), b"\x00\xd8")
    (event,) = collector.parse_events(collector.query(0, 1, run=lambda a: broken))
    assert event.record_id == 2 and "�" in event.fields["TargetUserName"]


class Done:
    def __init__(self, code: int, out: bytes = b"") -> None:
        self.returncode = code
        self.stdout = out
        self.stderr = b"segredo-do-sistema"


def test_run_wevtutil_maps_exit_codes(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []
    codes = [0]

    def fake_run(cmd: list[str], **kw: Any) -> Done:
        calls.append({"cmd": cmd, **kw})
        return Done(codes.pop(0), b"ok")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert collector.run_wevtutil(["qe", "Security"]) == b"ok"
    call = calls[0]
    assert call["shell"] is False and call["stdin"] is subprocess.DEVNULL
    assert Path(call["cmd"][0]).name == "wevtutil.exe" and Path(call["cmd"][0]).is_absolute()
    codes[:] = [5]
    with pytest.raises(AccessDenied, match="Event Log Readers"):
        collector.run_wevtutil(["qe"])
    codes[:] = [15007]
    with pytest.raises(CollectorError, match="15007") as err:
        collector.run_wevtutil(["qe"])
    assert "segredo-do-sistema" not in str(err.value)  # stderr nunca vai para a mensagem


def test_run_wevtutil_timeout_and_missing_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    def timeout(*a: Any, **k: Any) -> Done:
        raise subprocess.TimeoutExpired("wevtutil", 30)

    def missing(*a: Any, **k: Any) -> Done:
        raise FileNotFoundError

    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(CollectorError):
        collector.run_wevtutil(["qe"])
    monkeypatch.setattr(subprocess, "run", missing)
    with pytest.raises(CollectorError):
        collector.run_wevtutil(["qe"])


def test_run_wevtutil_output_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(collector, "MAX_OUTPUT_BYTES", 10)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: Done(0, b"x" * 11))
    with pytest.raises(CollectorError, match="limite"):
        collector.run_wevtutil(["qe"])


def test_check_access_propagates_denial() -> None:
    def denied(args: list[str]) -> bytes:
        raise AccessDenied("sem acesso")

    with pytest.raises(AccessDenied):
        collector.check_access(run=denied)
    collector.check_access(run=lambda a: b"")

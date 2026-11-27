"""Eventos sintéticos no formato do ``wevtutil`` (nunca log real)."""

from xml.sax.saxutils import escape

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
AGENT_ID = "0b0b0b0b-1111-4222-8333-444455556666"
CREDENTIAL = "ares_agent_" + AGENT_ID.replace("-", "") + "." + "A" * 43


def event_xml(
    windows_event_id: int,
    record_id: int,
    data: dict[str, str] | None = None,
    when: str = "2026-11-27T19:34:23.2558926Z",
) -> str:
    items = "".join(f"<Data Name='{k}'>{escape(v)}</Data>" for k, v in (data or {}).items())
    return (
        f"<Event xmlns='{NS}'><System>"
        "<Provider Name='Microsoft-Windows-Security-Auditing'/>"
        f"<EventID>{windows_event_id}</EventID><Version>2</Version><Level>0</Level>"
        f"<TimeCreated SystemTime='{when}'/><EventRecordID>{record_id}</EventRecordID>"
        "<Channel>Security</Channel><Computer>LAB-PC</Computer></System>"
        f"<EventData>{items}</EventData></Event>"
    )


def logon_failure(record_id: int, user: str = "maria") -> str:
    return event_xml(
        4625,
        record_id,
        {
            "TargetUserName": user,
            "TargetDomainName": "LAB",
            "LogonType": "3",
            "WorkstationName": "PC-01",
            "IpAddress": "10.0.0.5",
            "ProcessName": "-",
            "Status": "0xc000006d",
            "SubStatus": "0xc000006a",
            # Fora da lista: nunca podem sair do host.
            "CommandLine": "powershell -enc AAAA",
            "Password": "hunter2",
        },
    )

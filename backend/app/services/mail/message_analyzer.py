from email.message import EmailMessage

from app.services.eml.authentication import (
    analyze_authentication_headers,
)
from app.services.eml.reconstructor import reconstruct_hops
from app.services.risk.hndl import assess_hndl_exposure
from app.services.risk.scorer import calculate_security_score
from app.services.security.authentication import (
    analyze_authentication_security,
)
from app.services.security.findings import (
    analyze_transit_security,
)
from app.services.security.summary import (
    summarize_combined_findings,
)


def _build_email_message(message: dict) -> EmailMessage:
    email_message = EmailMessage()

    headers = message.get("headers") or {}

    for header_name, header_value in headers.items():
        if header_value is None:
            continue

        if isinstance(header_value, list):
            values = header_value
        else:
            values = [header_value]

        for value in values:
            if not isinstance(value, str):
                continue

            if value.strip().lower() == "unknown":
                continue

            try:
                email_message[header_name] = value
            except (TypeError, ValueError):
                continue

    return email_message


def _get_received_headers(message: dict) -> list[str]:
    headers = message.get("headers") or {}

    received = headers.get("Received", [])

    if isinstance(received, str):
        received = [received]

    if not isinstance(received, list):
        return []

    return [
        value
        for value in received
        if isinstance(value, str)
        and value.strip()
        and value.strip().lower() != "unknown"
    ]


def analyze_mailbox_message(message: dict) -> dict:
    email_message = _build_email_message(message)

    authentication = analyze_authentication_headers(
        email_message
    )

    received_headers = _get_received_headers(message)

    if received_headers:
        hops = reconstruct_hops(received_headers)
    else:
        hops = []

    transit_security = analyze_transit_security(hops)

    authentication_security = analyze_authentication_security(
        authentication
    )

    combined_summary = summarize_combined_findings(
        hop_analysis=transit_security["hop_analysis"],
        additional_findings=authentication_security["findings"],
    )

    security_analysis = {
        "hop_analysis": transit_security["hop_analysis"],
        "authentication": authentication_security,
        "summary": combined_summary,
        "evidence_source": "mailbox_message",
    }

    risk = calculate_security_score(
        combined_summary
    )

    hndl = assess_hndl_exposure(
        transit_security["hop_analysis"]
    )

    return {
        "security": security_analysis,
        "risk": risk,
        "hndl": hndl,
        "evidence_source": "mailbox_message",
    }
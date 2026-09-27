from email import policy
from email.parser import BytesParser
from pathlib import Path

from .authentication import analyze_authentication_headers


def parse_eml_file(file_path: str) -> dict:
    path = Path(file_path)

    with path.open("rb") as file:
        message = BytesParser(
            policy=policy.default
        ).parse(file)

    received_headers = message.get_all(
        "Received",
        [],
    )

    authentication = analyze_authentication_headers(
        message
    )

    return {
        "filename": path.name,
        "subject": message.get("Subject"),
        "from": message.get("From"),
        "to": message.get("To"),
        "date": message.get("Date"),
        "message_id": message.get("Message-ID"),
        "received_headers": received_headers,
        "received_count": len(received_headers),
        "authentication": authentication,
    }
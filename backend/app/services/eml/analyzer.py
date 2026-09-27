from app.services.eml.entities import extract_entities
from app.services.risk.hndl import assess_hndl_exposure
from app.services.risk.scorer import calculate_security_score
from app.services.security.authentication import (
    analyze_authentication_security,
)
from app.services.security.findings import analyze_transit_security
from app.services.security.summary import summarize_combined_findings

from .parser import parse_eml_file
from .reconstructor import reconstruct_hops


def analyze_eml(file_path: str) -> dict:
    parsed_email = parse_eml_file(file_path)

    hops = reconstruct_hops(
        parsed_email["received_headers"]
    )

    entities = extract_entities(hops)

    transit_security = analyze_transit_security(
        hops
    )

    authentication_security = (
        analyze_authentication_security(
            parsed_email["authentication"]
        )
    )

    combined_summary = summarize_combined_findings(
        hop_analysis=transit_security["hop_analysis"],
        additional_findings=authentication_security[
            "findings"
        ],
    )

    security_analysis = {
        "hop_analysis": transit_security[
            "hop_analysis"
        ],
        "authentication": authentication_security,
        "summary": combined_summary,
    }

    risk = calculate_security_score(
        combined_summary
    )

    hndl = assess_hndl_exposure(
        transit_security["hop_analysis"]
    )

    return {
        "email": {
            "filename": parsed_email["filename"],
            "subject": parsed_email["subject"],
            "from": parsed_email["from"],
            "to": parsed_email["to"],
            "date": parsed_email["date"],
            "message_id": parsed_email["message_id"],
        },
        "transit": {
            "hop_count": len(hops),
            "hops": hops,
        },
        "authentication": parsed_email["authentication"],
        "entities": entities,
        "security": security_analysis,
        "risk": risk,
        "hndl": hndl,
    }
def assess_hndl_exposure(hop_analysis: list[dict]) -> dict:
    total_hops = len(hop_analysis)

    unknown_hops = 0
    tls_indicated_hops = 0

    for hop in hop_analysis:
        findings = hop.get("findings", [])

        has_unknown = any(
            finding.get("severity") == "unknown"
            for finding in findings
        )

        has_tls_indication = any(
            finding.get("finding") == "TLS-protected SMTP is indicated by the Received header."
            for finding in findings
        )

        if has_unknown:
            unknown_hops += 1

        if has_tls_indication:
            tls_indicated_hops += 1

    if total_hops == 0:
        level = "unknown"
        exposure_score = None
    else:
        exposure_ratio = unknown_hops / total_hops
        exposure_score = round(exposure_ratio * 100)

        if exposure_score == 0:
            level = "low"
        elif exposure_score < 50:
            level = "moderate"
        else:
            level = "elevated"

    return {
        "level": level,
        "exposure_score": exposure_score,
        "total_hops": total_hops,
        "unknown_transport_hops": unknown_hops,
        "tls_indicated_hops": tls_indicated_hops,
        "assessment": (
            "HNDL exposure cannot be fully determined from email headers alone. "
            "The indicator reflects transport-security uncertainty in observed hops, "
            "not evidence that encrypted content can currently be decrypted."
        ),
    }
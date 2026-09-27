def summarize_findings(hop_analysis: list[dict]) -> dict:
    findings = []

    for hop in hop_analysis:
        findings.extend(hop.get("findings", []))

    return _build_summary(findings)


def summarize_combined_findings(
    hop_analysis: list[dict],
    additional_findings: list[dict],
) -> dict:
    findings = []

    for hop in hop_analysis:
        findings.extend(hop.get("findings", []))

    findings.extend(additional_findings)

    return _build_summary(findings)


def _build_summary(findings: list[dict]) -> dict:
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0,
    }

    for finding in findings:
        severity = finding.get(
            "severity",
            "unknown",
        ).lower()

        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            severity_counts["unknown"] += 1

    return {
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "findings": findings,
    }
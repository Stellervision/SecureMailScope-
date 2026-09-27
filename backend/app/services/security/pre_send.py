def _count_findings(
    findings: list[dict],
    severity: str,
) -> int:
    return sum(
        1
        for finding in findings
        if finding.get("severity") == severity
    )


def _build_observability_summary(
    security: dict,
) -> dict:
    domain_summary = security.get(
        "domain_summary",
        {},
    )

    return {
        "live_transport_observation": domain_summary.get(
            "live_transport_observation",
            "unknown",
        ),
        "mx_hosts": domain_summary.get(
            "mx_hosts",
            0,
        ),
        "smtp_reachable_hosts": domain_summary.get(
            "smtp_reachable",
            0,
        ),
        "smtp_unreachable_hosts": domain_summary.get(
            "smtp_unreachable",
            0,
        ),
        "smtp_unobserved_hosts": domain_summary.get(
            "smtp_unobserved",
            0,
        ),
        "starttls_supported_hosts": domain_summary.get(
            "starttls_supported",
            0,
        ),
        "starttls_not_supported_hosts": domain_summary.get(
            "starttls_not_supported",
            0,
        ),
        "starttls_unobserved_hosts": domain_summary.get(
            "starttls_unobserved",
            0,
        ),
        "successful_tls_handshakes": domain_summary.get(
            "tls_successful",
            0,
        ),
        "tls_unobserved_hosts": domain_summary.get(
            "tls_unobserved",
            0,
        ),
        "tlsa_records": domain_summary.get(
            "tlsa_records",
            0,
        ),
        "tlsa_no_records": domain_summary.get(
            "tlsa_no_records",
            0,
        ),
    }


def _build_unknowns(
    security: dict,
) -> list[str]:
    domain_summary = security.get(
        "domain_summary",
        {},
    )

    unknowns = []

    smtp_unreachable = domain_summary.get(
        "smtp_unreachable",
        0,
    )

    smtp_unobserved = domain_summary.get(
        "smtp_unobserved",
        0,
    )

    starttls_unobserved = domain_summary.get(
        "starttls_unobserved",
        0,
    )

    tls_unobserved = domain_summary.get(
        "tls_unobserved",
        0,
    )

    if smtp_unreachable > 0 or smtp_unobserved > 0:
        unknowns.append(
            (
                "SMTP reachability could not be observed for "
                "one or more MX hosts from the assessment "
                "environment."
            )
        )

    if starttls_unobserved > 0:
        unknowns.append(
            (
                "STARTTLS support could not be observed for "
                "one or more MX hosts."
            )
        )

    if tls_unobserved > 0:
        unknowns.append(
            (
                "TLS handshake details could not be observed "
                "for one or more MX hosts."
            )
        )

    return unknowns


def _build_observations(
    security: dict,
    mta_sts: dict | None = None,
) -> list[str]:
    domain_summary = security.get(
        "domain_summary",
        {},
    )

    observations = []

    starttls_supported = domain_summary.get(
        "starttls_supported",
        0,
    )

    starttls_not_supported = domain_summary.get(
        "starttls_not_supported",
        0,
    )

    tls_successful = domain_summary.get(
        "tls_successful",
        0,
    )

    tlsa_records = domain_summary.get(
        "tlsa_records",
        0,
    )

    tlsa_no_records = domain_summary.get(
        "tlsa_no_records",
        0,
    )

    if starttls_supported > 0:
        observations.append(
            (
                f"STARTTLS was observed on "
                f"{starttls_supported} MX host(s)."
            )
        )

    if starttls_not_supported > 0:
        observations.append(
            (
                f"STARTTLS was not supported on "
                f"{starttls_not_supported} MX host(s)."
            )
        )

    if tls_successful > 0:
        observations.append(
            (
                f"Successful TLS handshakes were observed "
                f"on {tls_successful} MX host(s)."
            )
        )

    if tlsa_records > 0:
        observations.append(
            (
                f"TLSA records were observed for "
                f"{tlsa_records} MX host(s)."
            )
        )

    if tlsa_no_records > 0:
        observations.append(
            (
                f"No TLSA record was observed for "
                f"{tlsa_no_records} MX host(s)."
            )
        )

    if isinstance(mta_sts, dict):
        policy_result = mta_sts.get(
            "policy",
            {},
        )

        if isinstance(policy_result, dict):
            policy = policy_result.get(
                "policy",
                {},
            )

            if isinstance(policy, dict):
                mode = (
                    policy.get("mode") or ""
                ).lower()

                if mode == "enforce":
                    observations.append(
                        "An MTA-STS policy was observed in enforce mode."
                    )

    return observations


def _build_user_message(
    risk: dict,
    critical_count: int,
    high_count: int,
    unknowns: list[str],
) -> str:
    risk_level = (
        risk.get("risk_level")
        or "unknown"
    )

    if critical_count > 0:
        return (
            "Critical security findings were observed for the "
            "recipient domain. Review the findings before sending."
        )

    if high_count > 0:
        return (
            "High-severity security findings were observed for the "
            "recipient domain. Review the findings before sending."
        )

    if unknowns:
        return (
            "The recipient domain has observable security controls, "
            "but some transport properties could not be verified "
            "from the current assessment environment."
        )

    if risk_level == "low":
        return (
            "No high-severity security issue was observed in the "
            "available recipient-domain evidence."
        )

    if risk_level == "medium":
        return (
            "Some security considerations were observed for the "
            "recipient domain. Review the findings before sending."
        )

    return (
        "The recipient domain could not be fully assessed. "
        "Review the available evidence before sending."
    )


def build_pre_send_security_decision(
    recipient_email: str,
    domain: str,
    security: dict,
    recommendations: list[dict] | None = None,
    mta_sts: dict | None = None,
) -> dict:
    if not isinstance(security, dict):
        security = {}

    if not isinstance(recommendations, list):
        recommendations = []

    if not isinstance(mta_sts, dict):
        mta_sts = {}

    findings = security.get(
        "findings",
        [],
    )

    if not isinstance(findings, list):
        findings = []

    risk = security.get(
        "risk",
        {},
    )

    if not isinstance(risk, dict):
        risk = {}

    critical_count = _count_findings(
        findings,
        "critical",
    )

    high_count = _count_findings(
        findings,
        "high",
    )

    medium_count = _count_findings(
        findings,
        "medium",
    )

    unknown_count = _count_findings(
        findings,
        "unknown",
    )

    observations = _build_observations(
        security=security,
        mta_sts=mta_sts,
    )

    unknowns = _build_unknowns(
        security
    )

    recommendation_count = len(
        recommendations
    )

    if critical_count > 0 or high_count > 0:
        decision = "review_required"
    elif unknowns:
        decision = "proceed_with_unknowns"
    else:
        decision = "proceed"

    if critical_count > 0 or high_count > 0:
        user_action = (
            "Review the security findings and recommendations "
            "before confirming the send."
        )
    elif unknowns:
        user_action = (
            "Review the available evidence and recommendations. "
            "You may proceed, but some recipient transport "
            "properties could not be verified."
        )
    else:
        user_action = (
            "Review the available evidence and confirm the "
            "message before sending."
        )

    return {
        "recipient": recipient_email,
        "domain": domain,
        "decision": decision,
        "risk": {
            "score": risk.get("score"),
            "risk_level": risk.get("risk_level"),
            "confidence": risk.get("confidence"),
            "observability": risk.get("observability"),
        },
        "finding_counts": {
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "unknown": unknown_count,
        },
        "observability": _build_observability_summary(
            security
        ),
        "observations": observations,
        "unknowns": unknowns,
        "recommendation_count": recommendation_count,
        "user_message": _build_user_message(
            risk=risk,
            critical_count=critical_count,
            high_count=high_count,
            unknowns=unknowns,
        ),
        "user_action": user_action,
        "assessment_limits": [
            (
                "Recipient-domain assessment reflects observable "
                "DNS and live infrastructure evidence only."
            ),
            (
                "An unknown result does not prove that the "
                "recipient infrastructure lacks a security control."
            ),
            (
                "Successful transport TLS observation does not "
                "establish end-to-end email security."
            ),
        ],
        "assessment_source": "live_domain_assessment",
    }
def _risk_level_from_score(score: int) -> str:
    if score >= 90:
        return "low"
    elif score >= 70:
        return "medium"
    elif score >= 40:
        return "high"
    else:
        return "critical"


def calculate_domain_security_score(
    domain_summary: dict,
    mta_sts_policy_result: dict,
    mx_status: str | None = None,
) -> dict:
    deductions = 0
    reasons = []

    total_mx_hosts = domain_summary.get("mx_hosts", 0)

    no_mail_exchanger = mx_status in {
        "not_found",
        "no_mx",
    }

    # A domain without MX records cannot receive mail securely (or at
    # all). It previously fell through to a "low" risk score of 90.
    if (
        mx_status is not None
        and (
            mx_status != "success"
            or total_mx_hosts == 0
        )
    ):
        return {
            "score": None,
            "risk_level": (
                "critical"
                if no_mail_exchanger
                else "unknown"
            ),
            "confidence": (
                "high"
                if no_mail_exchanger
                else "low"
            ),
            "observability": "not_applicable",
            "deductions": 0,
            "reasons": [
                {
                    "severity": (
                        "critical"
                        if no_mail_exchanger
                        else "unknown"
                    ),
                    "finding": (
                        "No MX records were found for this domain, "
                        "so it cannot receive email."
                        if no_mail_exchanger
                        else "MX records could not be resolved, so "
                        "the mail transport posture is unknown."
                    ),
                    "source": "dns",
                }
            ],
        }

    starttls = domain_summary.get("starttls", {})
    tlsa = domain_summary.get("tlsa", {})
    tls = domain_summary.get("tls", {})

    starttls_not_supported = starttls.get(
        "not_supported_hosts",
        0,
    )

    tls_successful = tls.get(
        "successful_handshakes",
        0,
    )

    tlsa_unobserved = tlsa.get(
        "unobserved_hosts",
        0,
    )

    if starttls_not_supported > 0:
        deductions += min(
            40,
            starttls_not_supported * 20,
        )

        reasons.append(
            {
                "severity": "high",
                "finding": (
                    "One or more MX hosts were observed without "
                    "STARTTLS support."
                ),
                "affected_hosts": starttls_not_supported,
                "source": "live_probe",
            }
        )

    policy_status = mta_sts_policy_result.get("status")
    policy = mta_sts_policy_result.get("policy")

    if policy_status == "success" and isinstance(policy, dict):
        mode = (policy.get("mode") or "").lower()

        if mode == "enforce":
            reasons.append(
                {
                    "severity": "info",
                    "finding": (
                        "An MTA-STS policy was observed in enforce mode."
                    ),
                    "source": "mta_sts_policy",
                }
            )

        elif mode == "testing":
            deductions += 10

            reasons.append(
                {
                    "severity": "medium",
                    "finding": (
                        "The observed MTA-STS policy uses testing mode "
                        "rather than enforce mode."
                    ),
                    "source": "mta_sts_policy",
                }
            )

        elif mode:
            deductions += 10

            reasons.append(
                {
                    "severity": "medium",
                    "finding": (
                        "The observed MTA-STS policy does not use "
                        "enforce mode."
                    ),
                    "evidence": mode,
                    "source": "mta_sts_policy",
                }
            )

        else:
            reasons.append(
                {
                    "severity": "unknown",
                    "finding": (
                        "An MTA-STS policy was retrieved, but its "
                        "mode could not be reliably determined."
                    ),
                    "source": "mta_sts_policy",
                }
            )

    elif policy_status == "not_found":
        deductions += 10

        reasons.append(
            {
                "severity": "medium",
                "finding": (
                    "No MTA-STS policy was observed."
                ),
                "source": "mta_sts_policy",
            }
        )

    elif policy_status in {"unavailable", "error"}:
        reasons.append(
            {
                "severity": "unknown",
                "finding": (
                    "MTA-STS policy status could not be reliably "
                    "assessed from the assessment environment."
                ),
                "source": "mta_sts_policy",
            }
        )

    else:
        reasons.append(
            {
                "severity": "unknown",
                "finding": (
                    "MTA-STS policy status could not be fully determined."
                ),
                "source": "mta_sts_policy",
            }
        )

    if tlsa_unobserved > 0:
        reasons.append(
            {
                "severity": "unknown",
                "finding": (
                    "TLSA/DANE status could not be observed for "
                    "one or more MX hosts."
                ),
                "affected_hosts": tlsa_unobserved,
                "source": "dns",
            }
        )

    score = max(0, 100 - deductions)

    live_transport_observation = domain_summary.get(
        "live_transport_observation"
    )

    if total_mx_hosts == 0:
        observability = "not_applicable"
    elif live_transport_observation == "fully_observed":
        observability = "high"
    elif live_transport_observation == "partially_observed":
        observability = "partial"
    else:
        observability = "low"

    # Only "unknown" when nothing was observed. A host observed WITHOUT
    # STARTTLS is real evidence and must still produce a risk level.
    if (
        total_mx_hosts > 0
        and tls_successful == 0
        and starttls_not_supported == 0
    ):
        risk_level = "unknown"
    else:
        risk_level = _risk_level_from_score(score)

    if observability == "low":
        confidence = "low"
    elif observability == "partial":
        confidence = "medium"
    else:
        confidence = "high"

    return {
        "score": score if risk_level != "unknown" else None,
        "risk_level": risk_level,
        "confidence": confidence,
        "observability": observability,
        "deductions": deductions,
        "reasons": reasons,
    }
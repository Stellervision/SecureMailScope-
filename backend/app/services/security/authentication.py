# Shared severity for DKIM/DMARC results. Previously any non-pass
# result (including an explicit "fail") was scored "unknown", so a
# message failing DMARC with p=reject still scored 100/"low".
AUTHENTICATION_RESULT_SEVERITY = {
    "pass": "info",
    "fail": "high",
    "softfail": "medium",
    "permerror": "medium",
    "policy": "medium",
    "none": "medium",
    "neutral": "unknown",
    "temperror": "unknown",
    "multiple_observations": "unknown",
}

# Most severe first. Used so a "fail" is never masked by other results.
RESULT_PRIORITY = (
    "fail",
    "permerror",
    "softfail",
    "policy",
    "temperror",
    "none",
    "neutral",
)


def _spf_severity(result: str) -> str:
    severity_map = {
        "pass": "info",
        "fail": "high",
        "softfail": "medium",
        "neutral": "unknown",
        "none": "unknown",
        "temperror": "unknown",
        "permerror": "medium",
        "multiple_observations": "unknown",
    }

    return severity_map.get(
        result,
        "unknown",
    )


def _spf_finding_message(result: str) -> str:
    message_map = {
        "pass": (
            "An SPF pass result was observed in the "
            "message authentication headers."
        ),
        "fail": (
            "An SPF fail result was observed in the "
            "message authentication headers."
        ),
        "softfail": (
            "An SPF softfail result was observed in the "
            "message authentication headers."
        ),
        "neutral": (
            "An SPF neutral result was observed in the "
            "message authentication headers."
        ),
        "none": (
            "An SPF none result was observed in the "
            "message authentication headers."
        ),
        "temperror": (
            "An SPF temporary error result was observed "
            "in the message authentication headers."
        ),
        "permerror": (
            "An SPF permanent error result was observed "
            "in the message authentication headers."
        ),
        "multiple_observations": (
            "Multiple different SPF results were observed "
            "in the message authentication headers."
        ),
    }

    return message_map.get(
        result,
        (
            "An unrecognized SPF result was observed in "
            "the message authentication headers."
        ),
    )


def _determine_status(
    results: list[str],
    any_pass_wins: bool = False,
) -> str:
    unique_results = sorted(set(results))

    if len(unique_results) == 1:
        return unique_results[0]

    # DKIM: each signature is evaluated independently, and one valid
    # signature is sufficient (RFC 6376 section 6.1).
    if any_pass_wins and "pass" in unique_results:
        return "pass"

    # Mixed results used to collapse into "multiple_observations"
    # (severity unknown), which hid an observed "fail".
    for result in RESULT_PRIORITY:
        if result in unique_results:
            return result

    return "multiple_observations"


def _analyze_spf(
    authentication: dict,
) -> tuple[dict, list[dict]]:
    observations = authentication.get(
        "method_observations",
        {},
    ).get("spf", [])

    findings = []

    if not observations:
        return (
            {
                "status": "unobserved",
                "observations": [],
            },
            findings,
        )

    results = [
        observation.get("result")
        for observation in observations
        if observation.get("result")
    ]

    if not results:
        return (
            {
                "status": "unobserved",
                "observations": observations,
            },
            findings,
        )

    status = _determine_status(results)

    findings.append(
        {
            "severity": _spf_severity(status),
            "finding": _spf_finding_message(status),
            "evidence": {
                "results": results,
                "sources": [
                    observation.get("source")
                    for observation in observations
                ],
            },
            "source": "observed_header",
        }
    )

    return (
        {
            "status": status,
            "observations": observations,
        },
        findings,
    )


def _analyze_dkim(
    authentication: dict,
) -> tuple[dict, list[dict]]:
    signatures = authentication.get(
        "dkim_signatures",
        [],
    )

    observations = authentication.get(
        "method_observations",
        {},
    ).get("dkim", [])

    findings = []

    results = [
        observation.get("result")
        for observation in observations
        if observation.get("result")
    ]

    if results:
        status = _determine_status(
            results,
            any_pass_wins=True,
        )

        findings.append(
            {
                "severity": AUTHENTICATION_RESULT_SEVERITY.get(
                    status,
                    "unknown",
                ),
                "finding": (
                    "A DKIM authentication result was "
                    f"observed: {status}."
                ),
                "evidence": {
                    "results": results,
                    "sources": [
                        observation.get("source")
                        for observation in observations
                    ],
                },
                "source": "observed_header",
            }
        )
    else:
        status = "unobserved"

    if signatures:
        findings.append(
            {
                "severity": "info",
                "finding": (
                    "One or more DKIM signatures were observed "
                    "in the message headers. Cryptographic "
                    "validity was not independently verified."
                ),
                "evidence": {
                    "signature_count": len(signatures),
                    "signatures": signatures,
                },
                "source": "observed_header",
            }
        )

    return (
        {
            "status": status,
            "authentication_observations": observations,
            "signature_count": len(signatures),
            "signatures": signatures,
        },
        findings,
    )


def _analyze_dmarc(
    authentication: dict,
) -> tuple[dict, list[dict]]:
    observations = authentication.get(
        "method_observations",
        {},
    ).get("dmarc", [])

    findings = []

    if not observations:
        return (
            {
                "status": "unobserved",
                "observations": [],
            },
            findings,
        )

    results = [
        observation.get("result")
        for observation in observations
        if observation.get("result")
    ]

    if not results:
        return (
            {
                "status": "unobserved",
                "observations": observations,
            },
            findings,
        )

    status = _determine_status(results)

    severity = AUTHENTICATION_RESULT_SEVERITY.get(
        status,
        "unknown",
    )

    findings.append(
        {
            "severity": severity,
            "finding": (
                "A DMARC authentication result was "
                f"observed: {status}."
            ),
            "evidence": {
                "results": results,
                "sources": [
                    observation.get("source")
                    for observation in observations
                ],
            },
            "source": "observed_header",
        }
    )

    return (
        {
            "status": status,
            "observations": observations,
        },
        findings,
    )


def analyze_authentication_security(
    authentication: dict,
) -> dict:
    spf_summary, spf_findings = _analyze_spf(
        authentication
    )

    dkim_summary, dkim_findings = _analyze_dkim(
        authentication
    )

    dmarc_summary, dmarc_findings = _analyze_dmarc(
        authentication
    )

    return {
        "findings": (
            spf_findings
            + dkim_findings
            + dmarc_findings
        ),
        "summary": {
            "spf": spf_summary,
            "dkim": dkim_summary,
            "dmarc": dmarc_summary,
            "arc": {},
        },
        "evidence_source": authentication.get(
            "evidence_source",
            "unknown",
        ),
    }
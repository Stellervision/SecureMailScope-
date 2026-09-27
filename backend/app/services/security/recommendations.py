def _recommendation(
    recommendation_id: str,
    title: str,
    priority: str,
    status: str,
    why_it_matters: str,
    action: str,
    verification: str,
    evidence: list[str],
    applies_when: str,
) -> dict:
    return {
        "id": recommendation_id,
        "title": title,
        "priority": priority,
        "status": status,
        "why_it_matters": why_it_matters,
        "action": action,
        "verification": verification,
        "evidence": evidence,
        "applies_when": applies_when,
    }


def build_domain_recommendations(
    domain: str,
    security: dict,
    risk: dict,
    pqc: dict,
    mta_sts: dict,
) -> list[dict]:
    recommendations = []

    summary = security.get(
        "domain_summary",
        {},
    )

    starttls_not_supported = summary.get(
        "starttls",
        {},
    ).get(
        "not_supported_hosts",
        0,
    )

    starttls_unobserved = summary.get(
        "starttls",
        {},
    ).get(
        "unobserved_hosts",
        0,
    )

    tls_successful = summary.get(
        "tls",
        {},
    ).get(
        "successful_handshakes",
        0,
    )

    total_mx = summary.get(
        "mx_hosts",
        0,
    )

    tlsa_unobserved = summary.get(
        "tlsa",
        {},
    ).get(
        "unobserved_hosts",
        0,
    )

    mta_sts_dns_status = (
        mta_sts.get(
            "dns",
            {},
        ).get(
            "status",
            "unknown",
        )
    )

    if starttls_not_supported > 0:
        recommendations.append(
            _recommendation(
                recommendation_id="smtp-starttls",
                title="Enable STARTTLS on SMTP receiving servers",
                priority="high",
                status="actionable",
                why_it_matters=(
                    "SMTP servers that do not advertise STARTTLS "
                    "cannot negotiate transport encryption for "
                    "that receiving service."
                ),
                action=(
                    "Enable STARTTLS on the affected MX hosts, "
                    "configure a valid TLS certificate, and "
                    "apply an appropriate transport-security "
                    "policy where supported."
                ),
                verification=(
                    "Re-run the recipient security assessment and "
                    "confirm that each affected MX host advertises "
                    "STARTTLS and completes a TLS handshake."
                ),
                evidence=[
                    (
                        f"{starttls_not_supported} MX host(s) "
                        "were reachable but did not advertise "
                        "STARTTLS."
                    ),
                ],
                applies_when=(
                    "A live SMTP probe reached an MX host and "
                    "observed STARTTLS as unavailable."
                ),
            )
        )

    if (
        total_mx > 0
        and tls_successful == 0
        and starttls_unobserved > 0
    ):
        recommendations.append(
            _recommendation(
                recommendation_id="verify-smtp-transport",
                title="Verify SMTP transport encryption",
                priority="medium",
                status="verification_required",
                why_it_matters=(
                    "The assessment could not complete a live "
                    "SMTP/TLS observation for one or more "
                    "recipient MX hosts."
                ),
                action=(
                    "Do not interpret this observation as proof "
                    "that the recipient infrastructure lacks "
                    "TLS. Verify SMTP connectivity from an "
                    "authorized environment with permitted "
                    "outbound port-25 access."
                ),
                verification=(
                    "Repeat the assessment from an environment "
                    "where the MX hosts can be reached on TCP "
                    "port 25 and inspect the resulting STARTTLS "
                    "and TLS observations."
                ),
                evidence=[
                    (
                        f"{starttls_unobserved} MX host(s) have "
                        "unobserved STARTTLS status."
                    ),
                    (
                        "No successful live TLS handshake was "
                        "observed."
                    ),
                ],
                applies_when=(
                    "SMTP/TLS cannot be observed from the current "
                    "assessment environment."
                ),
            )
        )

    if mta_sts_dns_status == "not_found":
        recommendations.append(
            _recommendation(
                recommendation_id="mta-sts",
                title="Consider deploying MTA-STS",
                priority="medium",
                status="actionable",
                why_it_matters=(
                    "MTA-STS can publish a policy that tells "
                    "supporting mail systems how to handle "
                    "SMTP delivery when TLS cannot be negotiated."
                ),
                action=(
                    "Publish an _mta-sts TXT record and host a "
                    "valid MTA-STS policy containing the required "
                    "version, mode, MX patterns, and max_age values."
                ),
                verification=(
                    "Re-run the assessment and confirm that both "
                    "the MTA-STS DNS record and policy endpoint "
                    "are observable and valid."
                ),
                evidence=[
                    "No MTA-STS DNS record was observed.",
                ],
                applies_when=(
                    "The MTA-STS DNS record was successfully "
                    "queried and no valid record was found."
                ),
            )
        )

    if tlsa_unobserved > 0:
        recommendations.append(
            _recommendation(
                recommendation_id="tlsa-verification",
                title="Verify DANE/TLSA availability",
                priority="low",
                status="verification_required",
                why_it_matters=(
                    "TLSA records can provide DNS-based certificate "
                    "association information when DANE is deployed."
                ),
                action=(
                    "If DANE is intended for the domain, verify the "
                    "required TLSA records and the DNSSEC configuration "
                    "supporting those records."
                ),
                verification=(
                    "Query the relevant _25._tcp MX TLSA records "
                    "from an authorized DNS environment and validate "
                    "their association with the intended certificates."
                ),
                evidence=[
                    "TLSA status was not fully observable.",
                ],
                applies_when=(
                    "TLSA DNS resolution was unavailable or "
                    "inconclusive for one or more MX hosts."
                ),
            )
        )

    pqc_readiness = pqc.get(
        "readiness",
        "unknown",
    )

    if pqc_readiness == "unknown":
        recommendations.append(
            _recommendation(
                recommendation_id="pqc-readiness",
                title="Establish a post-quantum migration baseline",
                priority="low",
                status="verification_required",
                why_it_matters=(
                    "Current observations do not provide enough "
                    "TLS evidence to assess the domain's post-quantum "
                    "migration readiness."
                ),
                action=(
                    "Document the domain's cryptographic migration "
                    "plan and evaluate support for appropriate "
                    "post-quantum or hybrid mechanisms as standards "
                    "and infrastructure support mature."
                ),
                verification=(
                    "Reassess after obtaining observable TLS "
                    "handshake evidence and determine whether "
                    "post-quantum or hybrid mechanisms are actually "
                    "negotiated."
                ),
                evidence=[
                    (
                        "No successful TLS observation was available "
                        "for a meaningful PQC readiness assessment."
                    ),
                ],
                applies_when=(
                    "Live TLS evidence is insufficient to assess "
                    "post-quantum readiness."
                ),
            )
        )

    if pqc_readiness == "limited":
        recommendations.append(
            _recommendation(
                recommendation_id="pqc-migration",
                title="Review legacy TLS usage",
                priority="low",
                status="monitor",
                why_it_matters=(
                    "One or more observed TLS sessions used a "
                    "version older than TLS 1.3. This is not "
                    "evidence of post-quantum protection."
                ),
                action=(
                    "Review legacy TLS dependencies and establish "
                    "a migration path toward modern TLS configurations "
                    "where operationally appropriate."
                ),
                verification=(
                    "Repeat the assessment and confirm that observed "
                    "MX TLS sessions use the intended modern TLS "
                    "configuration."
                ),
                evidence=[
                    "Legacy TLS observations were detected.",
                    (
                        "TLS version alone does not demonstrate "
                        "post-quantum cryptographic protection."
                    ),
                ],
                applies_when=(
                    "At least one successful TLS observation used "
                    "a version older than TLS 1.3."
                ),
            )
        )

    if not recommendations:
        recommendations.append(
            _recommendation(
                recommendation_id="maintain-posture",
                title="Continue monitoring the observed security posture",
                priority="low",
                status="monitor",
                why_it_matters=(
                    "Email security posture can change as MX hosts, "
                    "TLS certificates, DNS records, and transport "
                    "policies change."
                ),
                action=(
                    "Periodically reassess the recipient domain and "
                    "investigate material changes in its observed "
                    "security configuration."
                ),
                verification=(
                    "Run a fresh assessment and compare the newly "
                    "observed evidence with the previous assessment."
                ),
                evidence=[
                    (
                        "No additional actionable recommendation "
                        "was triggered by the current evidence."
                    ),
                ],
                applies_when=(
                    "The current assessment does not identify a "
                    "specific actionable configuration issue."
                ),
            )
        )

    return recommendations
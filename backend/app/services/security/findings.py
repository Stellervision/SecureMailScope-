import re

from app.services.security.summary import summarize_findings


# RFC 3848 / RFC 8314 "with" keywords that indicate TLS. Gmail uses
# SMTPS/ESMTPS, authenticated submission uses ESMTPSA, etc.
TLS_PROTOCOLS = {
    "ESMTPS",
    "ESMTPSA",
    "SMTPS",
    "UTF8SMTPS",
    "UTF8SMTPSA",
    "LMTPS",
    "LMTPSA",
}

PLAIN_PROTOCOLS = {
    "SMTP",
    "ESMTP",
    "ESMTPA",
    "UTF8SMTP",
    "UTF8SMTPA",
    "LMTP",
}

# Postfix "(using TLSv1.3 ...)" and Exchange
# "with Microsoft SMTP Server (version=TLS1_2, ...)".
TLS_COMMENT_PATTERN = re.compile(
    r"\(using\s+TLS|version=TLS",
    re.IGNORECASE,
)


def analyze_hop_security(hop: dict) -> dict:
    protocol = (hop.get("protocol") or "").upper()

    raw_header = hop.get("raw_header") or ""

    findings = []

    tls_indicated = (
        protocol in TLS_PROTOCOLS
        or bool(
            TLS_COMMENT_PATTERN.search(
                raw_header
            )
        )
    )

    if tls_indicated or protocol in PLAIN_PROTOCOLS:
        # hndl.py matches the exact TLS finding text below.
        if tls_indicated:
            findings.append(
                {
                    "severity": "info",
                    "finding": "TLS-protected SMTP is indicated by the Received header.",
                    "evidence": protocol,
                    "source": "observed_header",
                }
            )
        else:
            findings.append(
                {
                    "severity": "unknown",
                    "finding": "The Received header indicates SMTP/ESMTP, but TLS details are not observable from this header alone.",
                    "evidence": protocol,
                    "source": "observed_header",
                }
            )
    else:
        findings.append(
            {
                "severity": "unknown",
                "finding": "Transport security could not be determined from the observed protocol field.",
                "evidence": protocol or None,
                "source": "observed_header",
            }
        )

    return {
        "hop": hop.get("hop"),
        "from": hop.get("from"),
        "from_ip": hop.get("from_ip"),
        "by": hop.get("by"),
        "protocol": hop.get("protocol"),
        "findings": findings,
    }


def analyze_transit_security(hops: list[dict]) -> dict:
    hop_analysis = [
        analyze_hop_security(hop)
        for hop in hops
    ]

    summary = summarize_findings(hop_analysis)

    return {
        "hop_analysis": hop_analysis,
        "summary": summary,
    }


def _build_mx_host_assessments(
    mx_records: list[dict],
    tlsa_results: list[dict],
    smtp_results: list[dict],
) -> list[dict]:
    tlsa_by_hostname = {
        result.get("hostname"): result
        for result in tlsa_results
        if result.get("hostname")
    }

    smtp_by_hostname = {
        result.get("hostname"): result
        for result in smtp_results
        if result.get("hostname")
    }

    assessments = []

    for mx_record in mx_records:
        hostname = mx_record.get("hostname")

        if not hostname:
            continue

        tlsa_result = tlsa_by_hostname.get(hostname)
        smtp_result = smtp_by_hostname.get(hostname)

        if tlsa_result is None:
            tlsa_status = "unobserved"
        else:
            tlsa_status = tlsa_result.get("status")

        if smtp_result is None:
            smtp_status = "unobserved"
            smtp_reachable = None
            starttls_supported = None
            tls_status = "unobserved"
        else:
            smtp_status = smtp_result.get("status")
            smtp_reachable = smtp_result.get("smtp_reachable")
            starttls_supported = smtp_result.get("starttls_supported")

            tls_result = smtp_result.get("tls")

            if (
                isinstance(tls_result, dict)
                and tls_result.get("status") == "success"
            ):
                tls_status = "success"
            elif smtp_result.get("status") == "unavailable":
                tls_status = "unobserved"
            else:
                tls_status = "unobserved"

        assessments.append(
            {
                "hostname": hostname,
                "preference": mx_record.get("preference"),
                "tlsa": {
                    "status": tlsa_status,
                    "records": (
                        tlsa_result.get("records", [])
                        if tlsa_result
                        else []
                    ),
                },
                "smtp": {
                    "status": smtp_status,
                    "reachable": smtp_reachable,
                    "starttls_supported": starttls_supported,
                },
                "tls": {
                    "status": tls_status,
                },
            }
        )

    return assessments


def _build_domain_summary(
    mx_host_assessments: list[dict],
) -> dict:
    total_hosts = len(mx_host_assessments)

    smtp_reachable = sum(
        1
        for host in mx_host_assessments
        if host["smtp"]["reachable"] is True
    )

    smtp_unreachable = sum(
        1
        for host in mx_host_assessments
        if host["smtp"]["status"] == "unavailable"
    )

    smtp_unobserved = sum(
        1
        for host in mx_host_assessments
        if host["smtp"]["status"] == "unobserved"
    )

    starttls_supported = sum(
        1
        for host in mx_host_assessments
        if host["smtp"]["starttls_supported"] is True
    )

    starttls_not_supported = sum(
        1
        for host in mx_host_assessments
        if host["smtp"]["starttls_supported"] is False
    )

    starttls_unobserved = sum(
        1
        for host in mx_host_assessments
        if host["smtp"]["starttls_supported"] is None
    )

    tls_successful = sum(
        1
        for host in mx_host_assessments
        if host["tls"]["status"] == "success"
    )

    tls_unobserved = sum(
        1
        for host in mx_host_assessments
        if host["tls"]["status"] == "unobserved"
    )

    tlsa_present = sum(
        1
        for host in mx_host_assessments
        if host["tlsa"]["status"] == "success"
        and host["tlsa"]["records"]
    )

    tlsa_absent = sum(
        1
        for host in mx_host_assessments
        if host["tlsa"]["status"] == "not_found"
    )

    tlsa_unobserved = sum(
        1
        for host in mx_host_assessments
        if host["tlsa"]["status"]
        not in {"success", "not_found"}
    )

    if total_hosts == 0:
        live_transport_observation = "not_applicable"
    elif tls_successful == total_hosts:
        live_transport_observation = "fully_observed"
    elif tls_successful > 0:
        live_transport_observation = "partially_observed"
    elif smtp_reachable > 0:
        live_transport_observation = "partially_observed"
    else:
        live_transport_observation = "unobserved"

    return {
        "mx_hosts": total_hosts,
        "smtp": {
            "reachable_hosts": smtp_reachable,
            "unreachable_hosts": smtp_unreachable,
            "unobserved_hosts": smtp_unobserved,
        },
        "starttls": {
            "supported_hosts": starttls_supported,
            "not_supported_hosts": starttls_not_supported,
            "unobserved_hosts": starttls_unobserved,
        },
        "tls": {
            "successful_handshakes": tls_successful,
            "unobserved_hosts": tls_unobserved,
        },
        "tlsa": {
            "hosts_with_records": tlsa_present,
            "hosts_without_records": tlsa_absent,
            "unobserved_hosts": tlsa_unobserved,
        },
        "live_transport_observation": live_transport_observation,
    }


def analyze_domain_security(
    domain: str,
    mx_result: dict,
    mta_sts_dns_result: dict,
    mta_sts_policy_result: dict,
    tlsa_results: list[dict],
    smtp_results: list[dict],
) -> dict:
    findings = []

    mx_status = mx_result.get("status")
    mx_records = mx_result.get("mx_records", [])

    if mx_status == "not_found":
        findings.append(
            {
                "severity": "high",
                "finding": "The assessed domain does not exist according to DNS.",
                "evidence": mx_result,
                "source": "dns",
            }
        )
    elif mx_status == "no_mx":
        findings.append(
            {
                "severity": "info",
                "finding": "No MX record was observed for the domain.",
                "evidence": mx_result,
                "source": "dns",
            }
        )
    elif mx_status in {"unavailable", "error"}:
        findings.append(
            {
                "severity": "unknown",
                "finding": "MX records could not be reliably assessed.",
                "evidence": mx_result,
                "source": "dns",
            }
        )
    elif mx_status == "invalid":
        findings.append(
            {
                "severity": "unknown",
                "finding": "The domain could not be assessed because the supplied domain name was invalid.",
                "evidence": mx_result,
                "source": "dns",
            }
        )
    elif mx_status == "success" and not mx_records:
        findings.append(
            {
                "severity": "unknown",
                "finding": "The DNS resolver reported success but returned no MX records.",
                "evidence": mx_result,
                "source": "dns",
            }
        )

    mta_sts_status = mta_sts_dns_result.get("status")
    mta_sts_record = mta_sts_dns_result.get("record")

    if mta_sts_status == "success" and mta_sts_record:
        findings.append(
            {
                "severity": "info",
                "finding": "An MTA-STS DNS record was observed for the domain.",
                "evidence": mta_sts_record,
                "source": "dns",
            }
        )
    elif mta_sts_status == "not_found":
        findings.append(
            {
                "severity": "medium",
                "finding": "No MTA-STS DNS record was observed for the domain.",
                "evidence": mta_sts_dns_result,
                "source": "dns",
            }
        )
    elif mta_sts_status in {"unavailable", "error"}:
        findings.append(
            {
                "severity": "unknown",
                "finding": "MTA-STS DNS status could not be reliably assessed.",
                "evidence": mta_sts_dns_result,
                "source": "dns",
            }
        )
    else:
        findings.append(
            {
                "severity": "unknown",
                "finding": "MTA-STS DNS status could not be fully determined.",
                "evidence": mta_sts_dns_result,
                "source": "dns",
            }
        )

    policy_status = mta_sts_policy_result.get("status")
    policy = mta_sts_policy_result.get("policy")

    if policy_status != "success" or not policy:
        findings.append(
            {
                "severity": "unknown",
                "finding": "An MTA-STS policy could not be fully observed.",
                "evidence": mta_sts_policy_result,
                "source": "mta_sts_policy",
            }
        )
    else:
        findings.append(
            {
                "severity": "info",
                "finding": "An MTA-STS policy was successfully retrieved.",
                "evidence": policy,
                "source": "mta_sts_policy",
            }
        )

        mode = (policy.get("mode") or "").lower()

        if mode == "enforce":
            findings.append(
                {
                    "severity": "info",
                    "finding": "The observed MTA-STS policy uses enforce mode.",
                    "evidence": mode,
                    "source": "mta_sts_policy",
                }
            )

    for tlsa_result in tlsa_results:
        hostname = tlsa_result.get("hostname")
        status = tlsa_result.get("status")

        if status == "success" and tlsa_result.get("records"):
            findings.append(
                {
                    "severity": "info",
                    "finding": "A TLSA record was observed for the MX host.",
                    "evidence": {
                        "hostname": hostname,
                        "records": tlsa_result.get("records"),
                    },
                    "source": "dns",
                }
            )
        elif status == "not_found":
            findings.append(
                {
                    "severity": "info",
                    "finding": "No TLSA record was observed for the MX host.",
                    "evidence": {
                        "hostname": hostname,
                        "record_name": tlsa_result.get("record_name"),
                    },
                    "source": "dns",
                }
            )
        else:
            findings.append(
                {
                    "severity": "unknown",
                    "finding": "TLSA/DANE status could not be fully determined for the MX host.",
                    "evidence": tlsa_result,
                    "source": "dns",
                }
            )

    for smtp_result in smtp_results:
        hostname = smtp_result.get("hostname")
        status = smtp_result.get("status")
        smtp_reachable = smtp_result.get("smtp_reachable")
        starttls_supported = smtp_result.get("starttls_supported")
        tls_result = smtp_result.get("tls")

        if status == "unavailable":
            findings.append(
                {
                    "severity": "unknown",
                    "finding": "SMTP transport could not be assessed because the MX host was unreachable from the assessment environment.",
                    "evidence": smtp_result,
                    "source": "live_probe",
                }
            )
        elif smtp_reachable is True and starttls_supported is False:
            findings.append(
                {
                    "severity": "high",
                    "finding": "The MX host accepted an SMTP connection but did not advertise STARTTLS.",
                    "evidence": {
                        "hostname": hostname,
                        "smtp_reachable": smtp_reachable,
                        "starttls_supported": starttls_supported,
                    },
                    "source": "live_probe",
                }
            )
        elif status == "tls_error":
            findings.append(
                {
                    "severity": "high",
                    "finding": "The MX host advertised STARTTLS, but the TLS negotiation failed.",
                    "evidence": {
                        "hostname": hostname,
                        "error": smtp_result.get("error"),
                    },
                    "source": "live_probe",
                }
            )
        elif smtp_reachable is True and starttls_supported is True:
            findings.append(
                {
                    "severity": "info",
                    "finding": "The MX host accepted an SMTP connection and advertised STARTTLS.",
                    "evidence": {
                        "hostname": hostname,
                        "smtp_reachable": smtp_reachable,
                        "starttls_supported": starttls_supported,
                    },
                    "source": "live_probe",
                }
            )

            if (
                isinstance(tls_result, dict)
                and tls_result.get("status") == "success"
            ):
                findings.append(
                    {
                        "severity": "info",
                        "finding": "A successful TLS handshake was observed after STARTTLS.",
                        "evidence": tls_result,
                        "source": "live_probe",
                    }
                )
        else:
            findings.append(
                {
                    "severity": "unknown",
                    "finding": "SMTP/STARTTLS security could not be fully determined for the MX host.",
                    "evidence": smtp_result,
                    "source": "live_probe",
                }
            )

    mx_host_assessments = _build_mx_host_assessments(
        mx_records=mx_records,
        tlsa_results=tlsa_results,
        smtp_results=smtp_results,
    )

    domain_summary = _build_domain_summary(
        mx_host_assessments
    )

    return {
        "domain": domain,
        "domain_summary": domain_summary,
        "mx_host_assessments": mx_host_assessments,
        "findings": findings,
    }
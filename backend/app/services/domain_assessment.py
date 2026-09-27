import re
from concurrent.futures import ThreadPoolExecutor

from app.services.dns.mta_sts import fetch_mta_sts_policy
from app.services.dns.policies import resolve_mta_sts
from app.services.dns.resolver import resolve_mx_records
from app.services.dns.tlsa import resolve_tlsa_record
from app.services.risk.domain_scorer import (
    calculate_domain_security_score,
)
from app.services.risk.pqc import assess_pqc_readiness
from app.services.security.findings import analyze_domain_security
from app.services.smtp.prober import probe_smtp_starttls


# Public DNS name with at least one dot and an alphabetic TLD. IP
# literals, "user@host" strings and single labels are rejected, because
# the domain is used to build the MTA-STS HTTPS URL and to open SMTP
# connections (otherwise e.g. "x@169.254.169.254" reached an internal
# address).
DOMAIN_PATTERN = re.compile(
    r"(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}"
)


def is_valid_domain(domain: str) -> bool:
    return bool(
        DOMAIN_PATTERN.fullmatch(
            domain or ""
        )
    )


def _probe_mx_services(mx_records: list[dict]) -> list[dict]:
    hostnames = [
        record["hostname"]
        for record in mx_records
        if record.get("hostname")
    ]

    if not hostnames:
        return []

    max_workers = min(5, len(hostnames))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(
            executor.map(
                probe_smtp_starttls,
                hostnames,
            )
        )

    return results


def _resolve_tlsa_records(
    mx_records: list[dict],
) -> list[dict]:
    hostnames = [
        record.get("hostname")
        for record in mx_records
        if record.get("hostname")
    ]

    if not hostnames:
        return []

    # TLSA lookups used to run one after another (up to 5 s each).
    # Running them in parallel keeps the pre-send check responsive.
    with ThreadPoolExecutor(
        max_workers=min(5, len(hostnames))
    ) as executor:
        return list(
            executor.map(
                resolve_tlsa_record,
                hostnames,
            )
        )


def _build_security_summary(
    smtp_results: list[dict],
) -> dict:
    total_mx = len(smtp_results)

    reachable = sum(
        1
        for result in smtp_results
        if result.get("smtp_reachable") is True
    )

    unreachable = sum(
        1
        for result in smtp_results
        if result.get("status") == "unavailable"
    )

    starttls_supported = sum(
        1
        for result in smtp_results
        if result.get("starttls_supported") is True
    )

    starttls_not_supported = sum(
        1
        for result in smtp_results
        if result.get("starttls_supported") is False
    )

    starttls_unobserved = sum(
        1
        for result in smtp_results
        if result.get("starttls_supported") is None
    )

    successful_tls = sum(
        1
        for result in smtp_results
        if (
            isinstance(result.get("tls"), dict)
            and result["tls"].get("status") == "success"
        )
    )

    tls_unobserved = sum(
        1
        for result in smtp_results
        if result.get("tls") is None
    )

    return {
        "mx_hosts": total_mx,
        "total_mx": total_mx,
        "smtp_reachable": reachable,
        "smtp_unreachable": unreachable,
        "smtp_unobserved": max(
            0,
            total_mx - reachable - unreachable,
        ),
        "starttls_supported": starttls_supported,
        "starttls_not_supported": starttls_not_supported,
        "starttls_unobserved": starttls_unobserved,
        "tls_successful": successful_tls,
        "tls_unobserved": tls_unobserved,
        "tlsa_records": 0,
        "tlsa_no_records": 0,
        "tlsa_unobserved": 0,
        "live_transport_observation": (
            "not_applicable"
            if total_mx == 0
            else "fully_observed"
            if successful_tls == total_mx
            else "partially_observed"
            if successful_tls > 0 or reachable > 0
            else "unobserved"
        ),
    }


def _merge_tls_summary(
    security_summary: dict,
    tlsa_results: list[dict],
) -> dict:
    tlsa_records = sum(
        1
        for result in tlsa_results
        if result.get("status") == "success"
        and result.get("records")
    )

    tlsa_no_records = sum(
        1
        for result in tlsa_results
        if result.get("status") == "not_found"
    )

    tlsa_unobserved = max(
        0,
        len(tlsa_results) - tlsa_records - tlsa_no_records,
    )

    return {
        **security_summary,
        "tlsa_records": tlsa_records,
        "tlsa_no_records": tlsa_no_records,
        "tlsa_unobserved": tlsa_unobserved,
    }


def analyze_domain(domain: str) -> dict:
    domain = domain.strip().lower().rstrip(".")

    if not domain:
        return {
            "status": "invalid",
            "domain": domain,
            "error": "A domain name is required.",
        }

    if not is_valid_domain(domain):
        return {
            "status": "invalid",
            "domain": domain,
            "error": "The value is not a valid public domain name.",
        }

    mx_result = resolve_mx_records(domain)

    mx_records = mx_result.get(
        "mx_records",
        [],
    )

    # MTA-STS DNS, MTA-STS HTTPS policy, TLSA and SMTP probes are
    # independent network operations, so they run concurrently.
    with ThreadPoolExecutor(
        max_workers=4
    ) as executor:
        mta_sts_dns_future = executor.submit(
            resolve_mta_sts,
            domain,
        )

        mta_sts_policy_future = executor.submit(
            fetch_mta_sts_policy,
            domain,
        )

        tlsa_future = executor.submit(
            _resolve_tlsa_records,
            mx_records,
        )

        smtp_future = executor.submit(
            _probe_mx_services,
            mx_records,
        )

        mta_sts_dns_result = mta_sts_dns_future.result()
        mta_sts_policy_result = mta_sts_policy_future.result()
        tlsa_results = tlsa_future.result()
        smtp_results = smtp_future.result()

    security_summary = _build_security_summary(
        smtp_results
    )

    security_summary = _merge_tls_summary(
        security_summary,
        tlsa_results,
    )

    security = analyze_domain_security(
        domain=domain,
        mx_result=mx_result,
        mta_sts_dns_result=mta_sts_dns_result,
        mta_sts_policy_result=mta_sts_policy_result,
        tlsa_results=tlsa_results,
        smtp_results=smtp_results,
    )

    # findings.py builds a nested summary (starttls.not_supported_hosts,
    # tls.successful_handshakes, ...) that the risk scorer and the
    # recommendation engine read, while pre_send.py reads the flat keys
    # built above. Overwriting one with the other made the risk score
    # always "unknown". The two shapes share no conflicting keys, so
    # both are kept.
    merged_summary = {
        **security.get(
            "domain_summary",
            {},
        ),
        **security_summary,
    }

    security["domain_summary"] = merged_summary

    risk = calculate_domain_security_score(
        domain_summary=merged_summary,
        mta_sts_policy_result=mta_sts_policy_result,
        mx_status=mx_result.get("status"),
    )

    tls_results = [
        result.get("tls")
        if result.get("tls")
        else {
            "status": "unavailable",
            "hostname": result.get("hostname"),
        }
        for result in smtp_results
    ]

    pqc = assess_pqc_readiness(
        tls_results
    )

    return {
        "status": "success",
        "domain": domain,
        "dns": {
            "mx": mx_result,
            "tlsa": tlsa_results,
        },
        "mta_sts": {
            "dns": mta_sts_dns_result,
            "policy": mta_sts_policy_result,
        },
        "smtp": smtp_results,
        "security": security,
        "risk": risk,
        "pqc": pqc,
    }
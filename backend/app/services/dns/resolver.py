import dns.exception
import dns.resolver


def resolve_mx_records(domain: str) -> dict:
    domain = domain.strip().lower().rstrip(".")

    if not domain:
        return {
            "domain": domain,
            "status": "invalid",
            "mx_records": [],
            "error": "A domain name is required.",
        }

    try:
        answers = dns.resolver.resolve(
            domain,
            "MX",
            lifetime=5,
        )

        records = []

        for answer in answers:
            records.append(
                {
                    "preference": int(answer.preference),
                    "hostname": str(answer.exchange).rstrip("."),
                }
            )

        records.sort(key=lambda record: record["preference"])

        return {
            "domain": domain,
            "status": "success",
            "mx_records": records,
            "error": None,
        }

    except dns.resolver.NXDOMAIN:
        return {
            "domain": domain,
            "status": "not_found",
            "mx_records": [],
            "error": "The domain does not exist.",
        }

    except dns.resolver.NoAnswer:
        return {
            "domain": domain,
            "status": "no_mx",
            "mx_records": [],
            "error": "No MX record was returned for the domain.",
        }

    except (
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return {
            "domain": domain,
            "status": "unavailable",
            "mx_records": [],
            "error": "DNS resolution was unavailable or timed out.",
        }

    except Exception as exc:
        return {
            "domain": domain,
            "status": "error",
            "mx_records": [],
            "error": str(exc),
        }
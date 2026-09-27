import dns.exception
import dns.resolver


def resolve_mta_sts(domain: str) -> dict:
    domain = domain.strip().lower().rstrip(".")
    record_name = f"_mta-sts.{domain}"

    if not domain:
        return {
            "domain": domain,
            "status": "invalid",
            "record": None,
            "error": "A domain name is required.",
        }

    try:
        answers = dns.resolver.resolve(
            record_name,
            "TXT",
            lifetime=5,
        )

        records = []

        for answer in answers:
            value = "".join(
                part.decode("utf-8")
                if isinstance(part, bytes)
                else str(part)
                for part in answer.strings
            )

            records.append(value)

        mta_sts_records = [
            record
            for record in records
            if record.lower().startswith("v=stsv1")
        ]

        if not mta_sts_records:
            return {
                "domain": domain,
                "status": "not_found",
                "record": None,
                "error": "No MTA-STS TXT record was found.",
            }

        return {
            "domain": domain,
            "status": "success",
            "record": mta_sts_records[0],
            "error": None,
        }

    except dns.resolver.NXDOMAIN:
        return {
            "domain": domain,
            "status": "not_found",
            "record": None,
            "error": "No MTA-STS TXT record was found.",
        }

    except dns.resolver.NoAnswer:
        return {
            "domain": domain,
            "status": "not_found",
            "record": None,
            "error": "No MTA-STS TXT record was returned.",
        }

    except (
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return {
            "domain": domain,
            "status": "unavailable",
            "record": None,
            "error": "DNS resolution was unavailable or timed out.",
        }

    except Exception as exc:
        return {
            "domain": domain,
            "status": "error",
            "record": None,
            "error": str(exc),
        }
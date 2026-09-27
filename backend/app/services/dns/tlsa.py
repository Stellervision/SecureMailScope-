import dns.exception
import dns.resolver


def resolve_tlsa_record(hostname: str, port: int = 25) -> dict:
    hostname = hostname.strip().lower().rstrip(".")

    if not hostname:
        return {
            "hostname": hostname,
            "port": port,
            "status": "invalid",
            "records": [],
            "error": "A hostname is required.",
        }

    record_name = f"_{port}._tcp.{hostname}"

    try:
        answers = dns.resolver.resolve(
            record_name,
            "TLSA",
            lifetime=5,
        )

        records = []

        for answer in answers:
            records.append(
                {
                    "usage": int(answer.usage),
                    "selector": int(answer.selector),
                    "matching_type": int(answer.mtype),
                    "certificate_association_data": answer.cert_association_data.hex(),
                }
            )

        return {
            "hostname": hostname,
            "port": port,
            "record_name": record_name,
            "status": "success",
            "records": records,
            "error": None,
        }

    except dns.resolver.NXDOMAIN:
        return {
            "hostname": hostname,
            "port": port,
            "record_name": record_name,
            "status": "not_found",
            "records": [],
            "error": "No TLSA record was found.",
        }

    except dns.resolver.NoAnswer:
        return {
            "hostname": hostname,
            "port": port,
            "record_name": record_name,
            "status": "not_found",
            "records": [],
            "error": "No TLSA record was returned.",
        }

    except (
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return {
            "hostname": hostname,
            "port": port,
            "record_name": record_name,
            "status": "unavailable",
            "records": [],
            "error": "TLSA DNS resolution was unavailable or timed out.",
        }

    except Exception as exc:
        return {
            "hostname": hostname,
            "port": port,
            "record_name": record_name,
            "status": "error",
            "records": [],
            "error": str(exc),
        }
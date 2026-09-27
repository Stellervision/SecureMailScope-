from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def fetch_mta_sts_policy(domain: str) -> dict:
    domain = domain.strip().lower().rstrip(".")

    if not domain:
        return {
            "domain": domain,
            "status": "invalid",
            "policy": None,
            "error": "A domain name is required.",
        }

    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"

    request = Request(
        url,
        headers={
            "User-Agent": "SecureMailScope/0.1",
            "Accept": "text/plain",
        },
    )

    try:
        with urlopen(request, timeout=8) as response:
            status_code = response.status
            content_type = response.headers.get("Content-Type", "")

            body = response.read(16 * 1024).decode(
                "utf-8",
                errors="replace",
            )

        if status_code != 200:
            return {
                "domain": domain,
                "status": "http_error",
                "policy": None,
                "http_status": status_code,
                "error": f"MTA-STS policy endpoint returned HTTP {status_code}.",
            }

        fields = {}
        mx_patterns = []

        for line in body.splitlines():
            line = line.strip()

            if not line or line.startswith("#") or ":" not in line:
                continue

            key, value = line.split(":", 1)

            key = key.strip().lower()
            value = value.strip()

            # RFC 8461 allows several "mx:" lines. They used to
            # overwrite each other so only the last one survived.
            if key == "mx":
                mx_patterns.append(value)
                fields["mx"] = ", ".join(mx_patterns)
                fields["mx_patterns"] = list(mx_patterns)
                continue

            fields[key] = value

        required_fields = {
            "version",
            "mode",
            "mx",
            "max_age",
        }

        missing_fields = sorted(
            required_fields - fields.keys()
        )

        if missing_fields:
            return {
                "domain": domain,
                "status": "invalid_policy",
                "policy": fields,
                "http_status": status_code,
                "content_type": content_type,
                "missing_fields": missing_fields,
                "error": "The MTA-STS policy is missing required fields.",
            }

        valid_modes = {
            "enforce",
            "testing",
            "none",
        }

        mode = fields.get("mode", "").lower()

        if mode not in valid_modes:
            return {
                "domain": domain,
                "status": "invalid_policy",
                "policy": fields,
                "http_status": status_code,
                "content_type": content_type,
                "missing_fields": [],
                "error": f"Unsupported MTA-STS mode: {mode or 'empty'}.",
            }

        return {
            "domain": domain,
            "status": "success",
            "policy": fields,
            "http_status": status_code,
            "content_type": content_type,
            "missing_fields": [],
            "error": None,
        }

    except HTTPError as exc:
        return {
            "domain": domain,
            "status": "http_error",
            "policy": None,
            "http_status": exc.code,
            "error": f"MTA-STS policy endpoint returned HTTP {exc.code}.",
        }

    except URLError as exc:
        return {
            "domain": domain,
            "status": "unavailable",
            "policy": None,
            "error": f"Unable to retrieve the MTA-STS policy: {exc.reason}",
        }

    except TimeoutError:
        return {
            "domain": domain,
            "status": "unavailable",
            "policy": None,
            "error": "MTA-STS policy retrieval timed out.",
        }

    except Exception as exc:
        return {
            "domain": domain,
            "status": "error",
            "policy": None,
            "error": str(exc),
        }
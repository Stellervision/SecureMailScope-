import re
from email.message import Message


AUTHENTICATION_HEADERS = (
    "Authentication-Results",
    "DKIM-Signature",
    "Received-SPF",
    "ARC-Authentication-Results",
)

AUTHENTICATION_RESULT_PATTERN = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)",
    re.IGNORECASE,
)


def _strip_comments(value: str) -> str:
    previous = None

    while previous != value:
        previous = value
        value = re.sub(
            r"\([^()]*\)",
            " ",
            value,
        )

    return value


def _parse_method_results(
    value: str,
) -> dict[str, list[str]]:
    """
    Returns every result per method, in header order.

    A dict comprehension used to keep only the LAST result per method,
    and comments such as Gmail's "arc=pass (i=1 spf=pass dkim=pass
    dmarc=pass)" were parsed as if they were real results. Comments are
    stripped first so only actual method results are counted.
    """

    method_results: dict[str, list[str]] = {}

    for method, result in AUTHENTICATION_RESULT_PATTERN.findall(
        _strip_comments(value)
    ):
        method_results.setdefault(
            method.lower(),
            [],
        ).append(result.lower())

    return method_results


def _get_all_headers(
    message: Message,
    header_name: str,
) -> list[str]:
    values = message.get_all(header_name, [])

    return [
        str(value)
        for value in values
        if value is not None
    ]


def _extract_authentication_results(
    message: Message,
) -> list[dict]:
    results = []

    for value in _get_all_headers(
        message,
        "Authentication-Results",
    ):
        method_results = _parse_method_results(
            value
        )

        methods = {
            method: results[0]
            for method, results in method_results.items()
        }

        results.append(
            {
                "header": "Authentication-Results",
                "value": value,
                "methods": methods,
                "method_results": method_results,
                "source": "observed_header",
            }
        )

    return results


def _extract_dkim_signatures(
    message: Message,
) -> list[dict]:
    signatures = []

    for value in _get_all_headers(
        message,
        "DKIM-Signature",
    ):
        signatures.append(
            {
                "header": "DKIM-Signature",
                "value": value,
                "source": "observed_header",
            }
        )

    return signatures


def _extract_received_spf(
    message: Message,
) -> list[dict]:
    results = []

    for value in _get_all_headers(
        message,
        "Received-SPF",
    ):
        result_match = re.match(
            r"\s*([a-z]+)\b",
            value,
            re.IGNORECASE,
        )

        result = (
            result_match.group(1).lower()
            if result_match
            else None
        )

        results.append(
            {
                "header": "Received-SPF",
                "value": value,
                "result": result,
                "source": "observed_header",
            }
        )

    return results


def _extract_arc_authentication_results(
    message: Message,
) -> list[dict]:
    results = []

    for value in _get_all_headers(
        message,
        "ARC-Authentication-Results",
    ):
        method_results = _parse_method_results(
            value
        )

        methods = {
            method: results[0]
            for method, results in method_results.items()
        }

        results.append(
            {
                "header": "ARC-Authentication-Results",
                "value": value,
                "methods": methods,
                "method_results": method_results,
                "source": "observed_header",
            }
        )

    return results


def _build_method_observations(
    authentication_results: list[dict],
    received_spf: list[dict],
) -> dict:
    observations = {
        "spf": [],
        "dkim": [],
        "dmarc": [],
    }

    for result in authentication_results:
        method_results = result.get(
            "method_results",
            {},
        )

        for method in observations:
            for method_result in method_results.get(
                method,
                [],
            ):
                observations[method].append(
                    {
                        "result": method_result,
                        "source": "Authentication-Results",
                    }
                )

    for result in received_spf:
        spf_result = result.get("result")

        if spf_result:
            observations["spf"].append(
                {
                    "result": spf_result,
                    "source": "Received-SPF",
                }
            )

    return observations


def analyze_authentication_headers(
    message: Message,
) -> dict:
    authentication_results = _extract_authentication_results(
        message
    )

    dkim_signatures = _extract_dkim_signatures(
        message
    )

    received_spf = _extract_received_spf(
        message
    )

    arc_authentication_results = (
        _extract_arc_authentication_results(
            message
        )
    )

    method_observations = _build_method_observations(
        authentication_results=authentication_results,
        received_spf=received_spf,
    )

    observed_header_count = (
        len(authentication_results)
        + len(dkim_signatures)
        + len(received_spf)
        + len(arc_authentication_results)
    )

    return {
        "authentication_results": authentication_results,
        "dkim_signatures": dkim_signatures,
        "received_spf": received_spf,
        "arc_authentication_results": arc_authentication_results,
        "method_observations": method_observations,
        "observed_header_count": observed_header_count,
        "evidence_source": "observed_header",
    }
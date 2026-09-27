import re


def _strip_comments(value: str) -> str:
    """
    Removes RFC 5322 comments, including nested ones.

    MTAs put TLS details inside comments, e.g. Postfix
    "(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 ...)". Matching
    "with" inside that comment produced the protocol "cipher".
    """

    previous = None

    while previous != value:
        previous = value
        value = re.sub(
            r"\([^()]*\)",
            " ",
            value,
        )

    return value


def reconstruct_hops(received_headers: list[str]) -> list[dict]:
    hops = []

    for index, header in enumerate(received_headers, start=1):
        # The raw header is still used for from_ip, because the
        # sender IP lives inside the "(host [1.2.3.4])" comment.
        header_without_comments = _strip_comments(
            header
        )

        from_match = re.search(
            r"\bfrom\s+([^\s(]+)",
            header_without_comments,
            re.IGNORECASE,
        )

        from_ip_match = re.search(
            r"\bfrom\s+[^\s(]+\s*\([^[]*\[([0-9a-fA-F:.]+)\]",
            header,
            re.IGNORECASE,
        )

        by_match = re.search(
            r"\bby\s+([^\s;]+)",
            header_without_comments,
            re.IGNORECASE,
        )

        with_match = re.search(
            r"\bwith\s+([A-Z0-9_-]+)",
            header_without_comments,
            re.IGNORECASE,
        )

        for_match = re.search(
            r"\bfor\s+<([^>]+)>",
            header_without_comments,
            re.IGNORECASE,
        )

        hops.append(
            {
                "hop": index,
                "from": from_match.group(1) if from_match else None,
                "from_ip": from_ip_match.group(1) if from_ip_match else None,
                "by": by_match.group(1) if by_match else None,
                "protocol": with_match.group(1) if with_match else None,
                "recipient": for_match.group(1) if for_match else None,
                "raw_header": header,
            }
        )

    return hops

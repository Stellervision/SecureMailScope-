import ipaddress


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _extract_domain(value: str) -> str | None:
    if not value or _is_ip_address(value):
        return None

    hostname = value.strip().strip("[]").rstrip(".")

    if not hostname or _is_ip_address(hostname):
        return None

    if "." not in hostname:
        return None

    parts = hostname.split(".")

    if len(parts) < 2:
        return None

    return ".".join(parts[-2:])


def extract_entities(hops: list[dict]) -> dict:
    hostnames = set()
    ip_addresses = set()
    domains = set()

    for hop in hops:
        for field in ("from", "by"):
            value = hop.get(field)

            if not value:
                continue

            # Address literals such as "[192.168.1.5]" must be
            # unbracketed before the IP check; they previously became
            # bogus hostnames/domains like "1.5]".
            hostname = value.strip().strip("[]").rstrip(".")

            if not hostname:
                continue

            if _is_ip_address(hostname):
                ip_addresses.add(hostname)
            else:
                hostnames.add(hostname)

                domain = _extract_domain(hostname)

                if domain:
                    domains.add(domain)

        from_ip = hop.get("from_ip")

        if from_ip and _is_ip_address(from_ip):
            ip_addresses.add(from_ip)

    return {
        "hostnames": sorted(hostnames),
        "ip_addresses": sorted(ip_addresses),
        "domains": sorted(domains),
    }
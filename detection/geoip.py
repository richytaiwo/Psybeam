import ipaddress

# Store some IP ranges for the demo
_PREFIX_TABLE = {
    "185.220.": ("Germany", True),
    "45.155.": ("Romania", True),
    "194.26.": ("Netherlands", True),
    "103.94.": ("Hong Kong", True),
    "203.0.113.": ("Test-Net (RFC5737)", True),
    "198.51.100.": ("Test-Net (RFC5737)", True),
    "91.219.": ("Ukraine", True),
}

HOME_COUNTRIES = {"Internal"}


def is_private(ip: str) -> bool:
    # Check if the IP is a private address
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def lookup_country(ip: str):
    """Returns (country, is_flagged_region)."""

    # Private IPs are treated as internal
    if is_private(ip):
        return "Internal", False

    # Check if the IP matches one of the stored ranges
    for prefix, (country, flagged) in _PREFIX_TABLE.items():
        if ip.startswith(prefix):
            return country, flagged

    # Use Unknown if the IP is not in the table
    return "Unknown", False


def enrich_ip(ip: str) -> dict:
    # Get the country and whether the IP is flagged
    country, flagged = lookup_country(ip)

    # Store the IP information
    return {
        "ip": ip,
        "country": country,
        "is_internal": is_private(ip),
        "flagged_region": flagged,
    }
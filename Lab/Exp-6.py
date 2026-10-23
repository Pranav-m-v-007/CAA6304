import argparse
import ipaddress
import json
import re
import socket
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, unquote


SUSPICIOUS_WORDS = {
    "login", "verify", "verification", "secure",
    "update", "account", "password", "signin",
    "wallet", "payment", "confirm", "recover",
    "suspended", "urgent", "gift", "free"
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co",
    "is.gd", "cutt.ly", "shorturl.at"
}


def resolve_domain(domain):
    """Attempt DNS resolution without assuming the domain is safe."""
    try:
        results = socket.getaddrinfo(
            domain,
            None,
            type=socket.SOCK_STREAM
        )

        return sorted({
            item[4][0] for item in results
        })

    except (socket.gaierror, OSError):
        return []


def analyse_url(raw_url, check_dns=False):
    raw_url = raw_url.strip()

    if not raw_url:
        raise ValueError("URL cannot be empty.")

    if any(ord(char) < 32 for char in raw_url):
        raise ValueError("URL contains control characters.")

    # Reject unsupported schemes rather than treating them as websites.
    if not re.match(r"^https?://", raw_url, re.IGNORECASE):
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("URL does not contain a valid hostname.")

    try:
        hostname = parsed.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValueError("Invalid internationalised domain.") from error

    score = 0
    findings = []

    def flag(points, description):
        nonlocal score
        score += points
        findings.append({
            "points": points,
            "finding": description
        })

    # 1. Unusually long URL.
    if len(raw_url) > 120:
        flag(10, "Unusually long URL.")

    # 2. Suspicious words in URL.
    decoded_url = unquote(raw_url).lower()

    matched_words = sorted(
        word for word in SUSPICIOUS_WORDS
        if re.search(
            r"(?<![a-z0-9])" + re.escape(word) +
            r"(?![a-z0-9])",
            decoded_url
        )
    )

    if matched_words:
        flag(
            min(20, len(matched_words) * 5),
            "Suspicious words found: " + ", ".join(matched_words)
        )

    # 3. IP address used as the hostname.
    is_ip = False

    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        pass

    if is_ip:
        flag(25, "Hostname is an IP address rather than a domain.")

    # 4. User information embedded before the hostname.
    if "@" in parsed.netloc:
        flag(20, "URL contains an @ sign in its network location.")

    # 5. Excessive subdomains.
    labels = hostname.rstrip(".").split(".")

    if not is_ip and len(labels) >= 5:
        flag(15, "Hostname contains many domain labels.")

    # 6. Punycode may indicate an internationalised domain.
    if any(label.startswith("xn--") for label in labels):
        flag(10, "Hostname contains a Punycode label.")

    # 7. HTTP is not encrypted.
    if parsed.scheme == "http":
        flag(5, "URL uses HTTP instead of HTTPS.")

    # 8. Known URL shorteners hide the final destination.
    if hostname in SHORTENER_DOMAINS:
        flag(10, "URL uses a recognised link-shortening service.")

    # 9. Validate hostname syntax.
    if not is_ip:
        valid_hostname = (
            len(hostname) <= 253
            and all(
                label
                and len(label) <= 63
                and not label.startswith("-")
                and not label.endswith("-")
                and re.fullmatch(r"[a-z0-9-]+", label)
                for label in labels
            )
            and "." in hostname
        )

        if not valid_hostname:
            flag(15, "Hostname has an unusual or invalid structure.")

    # DNS is optional because some environments have no internet access.
    resolved_addresses = None

    if check_dns and not is_ip:
        resolved_addresses = resolve_domain(hostname)

        if not resolved_addresses:
            flag(10, "Hostname could not be resolved through DNS.")

    # Bound the heuristic score.
    score = min(score, 100)

    if score >= 50:
        risk = "HIGH"
    elif score >= 25:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "url": raw_url,
        "hostname": hostname,
        "https_used": parsed.scheme == "https",
        "risk_score": score,
        "risk_level": risk,
        "findings": findings,
        "dns_addresses": resolved_addresses,
        "warning": (
            "Heuristic result only. A low score does not prove "
            "that a URL is safe."
        )
    }


def main():
    parser = argparse.ArgumentParser(
        description="Phishing URL heuristic analyser"
    )

    parser.add_argument(
        "url",
        nargs="?",
        help="URL to analyse"
    )

    parser.add_argument(
        "--dns",
        action="store_true",
        help="Attempt DNS resolution"
    )

    args = parser.parse_args()

    url = args.url or input("Enter URL to analyse: ")

    try:
        report = analyse_url(url, check_dns=args.dns)

        print("\nURL ANALYSIS")
        print("-" * 45)
        print("URL:", report["url"])
        print("Hostname:", report["hostname"])
        print("HTTPS:", report["https_used"])
        print("Risk score:", report["risk_score"], "/ 100")
        print("Risk level:", report["risk_level"])

        print("\nFindings:")

        if report["findings"]:
            for finding in report["findings"]:
                print(
                    f'- +{finding["points"]}: '
                    f'{finding["finding"]}'
                )
        else:
            print("No configured warning indicators detected.")

        if report["dns_addresses"] is not None:
            print("DNS addresses:", report["dns_addresses"])

        Path("phishing_report.json").write_text(
            json.dumps(report, indent=4),
            encoding="utf-8"
        )

        print("\nSaved report: phishing_report.json")

    except ValueError as error:
        print("Input error:", error)


if __name__ == "__main__":
    main()

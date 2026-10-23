import argparse
import concurrent.futures
import csv
import json
import socket
from datetime import datetime
from pathlib import Path


COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP Alternate",
    8443: "HTTPS Alternate"
}


def scan_port(host, port, timeout):
    result = {
        "port": port,
        "state": "closed_or_filtered",
        "service": COMMON_SERVICES.get(port, "Unknown"),
        "error": None
    }

    try:
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as sock:

            sock.settimeout(timeout)

            connection_result = sock.connect_ex(
                (host, port)
            )

            if connection_result == 0:
                result["state"] = "open"

    except socket.gaierror:
        result["state"] = "error"
        result["error"] = "Hostname resolution failed"

    except (OSError, TimeoutError) as error:
        result["state"] = "error"
        result["error"] = str(error)

    return result


def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as error:
        raise ValueError(
            f"Could not resolve target: {error}"
        ) from error


def scan_host(target, start_port, end_port, timeout, workers):
    ip_address = resolve_target(target)

    print(f"\nTarget: {target}")
    print(f"Resolved IP: {ip_address}")
    print(f"Port range: {start_port}-{end_port}")
    print("\nScanning...")

    results = []

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=workers
    ) as executor:

        futures = [
            executor.submit(
                scan_port,
                ip_address,
                port,
                timeout
            )
            for port in range(start_port, end_port + 1)
        ]

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)

            if result["state"] == "open":
                print(
                    f'[OPEN] {result["port"]:5} '
                    f'{result["service"]}'
                )

    results.sort(key=lambda item: item["port"])

    return ip_address, results


def save_reports(target, ip_address, results):
    timestamp = datetime.now().isoformat(timespec="seconds")

    report = {
        "timestamp": timestamp,
        "target": target,
        "resolved_ip": ip_address,
        "results": results
    }

    json_file = Path("port_scan_report.json")

    json_file.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8"
    )

    csv_file = Path("port_scan_report.csv")

    with csv_file.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=[
                "port",
                "state",
                "service",
                "error"
            ]
        )

        writer.writeheader()
        writer.writerows(results)

    return json_file, csv_file


def main():
    parser = argparse.ArgumentParser(
        description="TCP port scanner for authorized testing"
    )

    parser.add_argument(
        "target",
        help="Authorized hostname or IP address"
    )

    parser.add_argument(
        "--start",
        type=int,
        default=1,
        help="Starting port (default: 1)"
    )

    parser.add_argument(
        "--end",
        type=int,
        default=1024,
        help="Ending port (default: 1024)"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Connection timeout in seconds"
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=50,
        help="Maximum concurrent connection checks"
    )

    args = parser.parse_args()

    if not (
        1 <= args.start <= args.end <= 65535
    ):
        parser.error(
            "Ports must satisfy "
            "1 <= start <= end <= 65535"
        )

    if not 0.1 <= args.timeout <= 10:
        parser.error("Timeout must be between 0.1 and 10 seconds")

    if not 1 <= args.workers <= 100:
        parser.error("Workers must be between 1 and 100")

    try:
        ip_address, results = scan_host(
            args.target,
            args.start,
            args.end,
            args.timeout,
            args.workers
        )

        open_ports = [
            item for item in results
            if item["state"] == "open"
        ]

        print("\n" + "=" * 45)
        print("SCAN SUMMARY")
        print("=" * 45)

        print("Ports checked:", len(results))
        print("Open ports:", len(open_ports))

        if not open_ports:
            print("No open TCP ports detected.")

        json_file, csv_file = save_reports(
            args.target,
            ip_address,
            results
        )

        print("\nReports generated:")
        print(json_file.resolve())
        print(csv_file.resolve())

    except ValueError as error:
        print("Error:", error)


if __name__ == "__main__":
    main()

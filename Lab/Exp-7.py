import argparse
import json
import re
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"(?P<level>INFO|WARN|ERROR|DEBUG)\s+"
    r"(?P<source>\S+)\s+"
    r"(?P<event>\S+)"
    r"(?:\s+(?P<details>.*))?$",
    re.IGNORECASE
)


def parse_log_line(line):
    """Logstash-style parsing and normalisation."""

    match = LOG_PATTERN.match(line.strip())

    if not match:
        return None

    item = match.groupdict()

    details = {}

    for token in (item["details"] or "").split():
        if "=" in token:
            key, value = token.split("=", 1)
            details[key] = value

    try:
        timestamp = datetime.fromisoformat(
            item["timestamp"].replace("Z", "+00:00")
        )

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

    except ValueError:
        return None

    return {
        "timestamp": timestamp.isoformat(),
        "level": item["level"].upper(),
        "source": item["source"],
        "event": item["event"].upper(),
        "details": details,
        "raw": line.strip()
    }


def initialise_database(connection):
    connection.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            level TEXT NOT NULL,
            source TEXT NOT NULL,
            event TEXT NOT NULL,
            details TEXT NOT NULL,
            raw TEXT NOT NULL
        )
    """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_event_timestamp
        ON events(timestamp)
    """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_event_type
        ON events(event)
    """)

    connection.commit()


def ingest_logs(connection, log_path):
    path = Path(log_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Log file does not exist: {path}"
        )

    accepted = 0
    rejected = 0

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            event = parse_log_line(line)

            if event is None:
                rejected += 1
                continue

            connection.execute("""
                INSERT INTO events
                (timestamp, level, source, event, details, raw)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                event["timestamp"],
                event["level"],
                event["source"],
                event["event"],
                json.dumps(event["details"]),
                event["raw"]
            ))

            accepted += 1

    connection.commit()

    return accepted, rejected


def generate_dashboard(connection):
    total = connection.execute(
        "SELECT COUNT(*) FROM events"
    ).fetchone()[0]

    by_level = connection.execute("""
        SELECT level, COUNT(*)
        FROM events
        GROUP BY level
        ORDER BY COUNT(*) DESC
    """).fetchall()

    by_event = connection.execute("""
        SELECT event, COUNT(*)
        FROM events
        GROUP BY event
        ORDER BY COUNT(*) DESC
    """).fetchall()

    top_sources = connection.execute("""
        SELECT source, COUNT(*)
        FROM events
        GROUP BY source
        ORDER BY COUNT(*) DESC
        LIMIT 10
    """).fetchall()

    suspicious_events = connection.execute("""
        SELECT timestamp, level, source, event, details
        FROM events
        WHERE level = 'ERROR'
           OR event IN (
               'LOGIN_FAILURE',
               'MALWARE_DETECTED',
               'ACCESS_DENIED'
           )
        ORDER BY timestamp DESC
        LIMIT 100
    """).fetchall()

    return {
        "generated_at": datetime.now().isoformat(
            timespec="seconds"
        ),
        "total_events": total,
        "events_by_level": dict(by_level),
        "events_by_type": dict(by_event),
        "top_sources": [
            {"source": row[0], "count": row[1]}
            for row in top_sources
        ],
        "suspicious_events": [
            {
                "timestamp": row[0],
                "level": row[1],
                "source": row[2],
                "event": row[3],
                "details": json.loads(row[4])
            }
            for row in suspicious_events
        ]
    }


def main():
    parser = argparse.ArgumentParser(
        description="Local ELK-style security log pipeline"
    )

    parser.add_argument(
        "logfile",
        nargs="?",
        default="security.log"
    )

    parser.add_argument(
        "--database",
        default="security_events.db"
    )

    args = parser.parse_args()

    try:
        with sqlite3.connect(args.database) as connection:
            initialise_database(connection)

            accepted, rejected = ingest_logs(
                connection,
                args.logfile
            )

            dashboard = generate_dashboard(connection)

        Path("security_dashboard.json").write_text(
            json.dumps(dashboard, indent=4),
            encoding="utf-8"
        )

        print("\nLOG INGESTION")
        print("Accepted events:", accepted)
        print("Rejected lines:", rejected)

        print("\nDASHBOARD SUMMARY")
        print("Total indexed events:", dashboard["total_events"])

        print("\nEvents by severity:")
        for level, count in dashboard["events_by_level"].items():
            print(f"{level}: {count}")

        print("\nEvents by type:")
        for event, count in dashboard["events_by_type"].items():
            print(f"{event}: {count}")

        print("\nPotentially suspicious events:")
        for event in dashboard["suspicious_events"]:
            print(
                event["timestamp"],
                event["source"],
                event["event"]
            )

        print("\nDatabase:", args.database)
        print("Dashboard: security_dashboard.json")

    except (OSError, sqlite3.Error) as error:
        print("Processing error:", error)


if __name__ == "__main__":
    main()

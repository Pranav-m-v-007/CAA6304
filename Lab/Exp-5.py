import json
import re
from datetime import datetime
from pathlib import Path


INTELLIGENCE_RULES = {
    "Strategic": {
        "description": [
            "long-term risk",
            "business impact",
            "geopolitical threat",
            "industry-wide threat",
            "cybersecurity investment",
            "executive decision"
        ],
        "audience": [
            "executives",
            "senior management",
            "board of directors",
            "business leaders"
        ]
    },

    "Tactical": {
        "description": [
            "tactics techniques and procedures",
            "attack techniques",
            "MITRE ATT&CK",
            "lateral movement",
            "privilege escalation",
            "adversary behavior",
            "persistence technique"
        ],
        "audience": [
            "security analysts",
            "threat hunters",
            "security engineers",
            "detection engineers"
        ]
    },

    "Operational": {
        "description": [
            "active attack",
            "ongoing incident",
            "malicious IP address",
            "command and control server",
            "incident investigation",
            "attack infrastructure",
            "campaign indicators",
            "incident response"
        ],
        "audience": [
            "incident response team",
            "soc analysts",
            "incident responders",
            "security operations center"
        ]
    }
}


def normalize(text):
    return re.sub(r"\s+", " ", text.lower()).strip()


def classify_report(description, audience):
    if not description.strip():
        raise ValueError("Report description cannot be empty.")

    if not audience.strip():
        raise ValueError("Intended audience cannot be empty.")

    desc = normalize(description)
    aud = normalize(audience)

    results = {}

    for category, rules in INTELLIGENCE_RULES.items():
        score = 0
        evidence = []

        # Description evidence receives higher weight.
        for phrase in rules["description"]:
            if phrase in desc:
                score += 2
                evidence.append(
                    f"Description contains: {phrase}"
                )

        # Audience provides additional context.
        for phrase in rules["audience"]:
            if phrase in aud:
                score += 1
                evidence.append(
                    f"Audience contains: {phrase}"
                )

        results[category] = {
            "score": score,
            "evidence": evidence
        }

    ranked = sorted(
        results.items(),
        key=lambda item: item[1]["score"],
        reverse=True
    )

    highest_category, highest_result = ranked[0]
    second_result = ranked[1][1]

    if highest_result["score"] == 0:
        classification = "Uncertain"
        confidence = 0.0

    elif highest_result["score"] == second_result["score"]:
        classification = "Ambiguous"
        confidence = 0.0

    else:
        classification = highest_category

        total_score = sum(
            item["score"] for item in results.values()
        )

        confidence = round(
            highest_result["score"] / total_score * 100,
            2
        )

    return {
        "timestamp": datetime.now().isoformat(
            timespec="seconds"
        ),
        "description": description,
        "intended_audience": audience,
        "classification": classification,
        "confidence_score_percent": confidence,
        "evidence": (
            highest_result["evidence"]
            if classification not in ("Uncertain", "Ambiguous")
            else []
        ),
        "ranked_categories": {
            category: details["score"]
            for category, details in ranked
        }
    }


def main():
    print("=" * 55)
    print("THREAT INTELLIGENCE REPORT CLASSIFIER")
    print("=" * 55)

    description = input(
        "\nDescribe the intelligence report:\n"
    ).strip()

    audience = input(
        "\nWho will use this report?\n"
    ).strip()

    try:
        report = classify_report(description, audience)

        print("\nCLASSIFICATION:", report["classification"])

        print(
            "Confidence score:",
            report["confidence_score_percent"],
            "%"
        )

        print("\nSupporting evidence:")

        if report["evidence"]:
            for evidence in report["evidence"]:
                print("-", evidence)
        else:
            print("No decisive evidence found.")

        print("\nCategory scores:")

        for category, score in report["ranked_categories"].items():
            print(f"{category}: {score}")

        output = Path("intelligence_classification.json")

        output.write_text(
            json.dumps(report, indent=4),
            encoding="utf-8"
        )

        print("\nReport saved to:", output.resolve())

    except ValueError as error:
        print("Input error:", error)


if __name__ == "__main__":
    main()

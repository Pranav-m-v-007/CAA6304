def classify_priority(alert):

    alert = alert.lower()

    priority_keywords = {

        "P1 - Critical": [
            "data breach",
            "ransomware",
            "critical attack",
            "data theft"
        ],

        "P2 - High": [
            "malware",
            "unauthorized access",
            "server compromise",
            "privilege escalation"
        ],

        "P3 - Medium": [
            "multiple failed login",
            "suspicious activity",
            "port scanning"
        ],

        "P4 - Low": [
            "software update",
            "informational alert",
            "routine activity"
        ]
    }

    for priority, keywords in priority_keywords.items():

        if any(word in alert for word in keywords):

            return priority

    return "P4 - Low (Unclassified Alert)"


print("SOC ALERT PRIORITY CLASSIFIER")

alert = input("\nEnter SOC alert description: ")

priority = classify_priority(alert)

print("\nAssigned Priority:", priority)

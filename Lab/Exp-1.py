def identify_application(scenario):
    scenario = scenario.lower()

    applications = {
        "Banking Fraud Prevention": [
            "bank", "credit card", "transaction", "fraud"
        ],
        "Healthcare Data Protection": [
            "hospital", "patient", "medical", "health records"
        ],
        "E-Commerce Fraud Prevention": [
            "online shopping", "online store", "orders", "payment"
        ],
        "Cloud Security": [
            "cloud", "cloud storage", "virtual machine"
        ],
        "Telecommunication Security": [
            "telecom", "mobile network", "5g", "4g"
        ]
    }

    scores = {}

    for application, keywords in applications.items():
        scores[application] = sum(
            keyword in scenario for keyword in keywords
        )

    best = max(scores, key=scores.get)

    if scores[best] == 0:
        return "No application area identified"

    return best


scenario = input("Enter business scenario: ")
print("Threat Intelligence Application:",
      identify_application(scenario))

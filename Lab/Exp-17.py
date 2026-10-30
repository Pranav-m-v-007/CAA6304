def classify_control(description):
    description = description.lower()

    controls = {
        "Organizational Controls": [
            "policy", "risk management", "supplier", "incident management"
        ],
        "People Controls": [
            "employee", "training", "awareness", "staff"
        ],
        "Physical Controls": [
            "building", "server room", "door", "physical access"
        ],
        "Technological Controls": [
            "password", "encryption", "firewall", "antivirus", "network"
        ]
    }

    for domain, keywords in controls.items():
        for keyword in keywords:
            if keyword in description:
                return domain

    return "Unknown Control Domain"


description = input("Enter security control description: ")

result = classify_control(description)

print("Security Control Domain:", result)

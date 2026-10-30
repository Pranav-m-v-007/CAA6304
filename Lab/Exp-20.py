def classify_threat(description):
    description = description.lower()

    threats = {
        "Phishing": [
            "fake email", "password", "fraudulent link",
            "credentials", "impersonation"
        ],
        "DoS/DDoS": [
            "flooding", "traffic overload", "server overload",
            "denial of service", "ddos"
        ],
        "Malware": [
            "virus", "worm", "trojan", "malicious software",
            "ransomware"
        ],
        "Man-in-the-Middle": [
            "intercept", "communication", "eavesdropping",
            "middle attack", "packet interception"
        ]
    }

    for threat, keywords in threats.items():
        for keyword in keywords:
            if keyword in description:
                return threat

    return "Unknown Threat"


incident = input("Enter incident description: ")

print("Detected Threat:", classify_threat(incident))

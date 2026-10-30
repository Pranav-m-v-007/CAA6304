def identify_root_cause(description):

    description = description.lower()

    causes = {

        "Phishing": [
            "phishing",
            "fake email",
            "malicious link",
            "credential theft"
        ],

        "Unpatched Vulnerability": [
            "unpatched",
            "outdated software",
            "missing security update",
            "known vulnerability"
        ],

        "Misconfiguration": [
            "misconfiguration",
            "wrong settings",
            "open port",
            "default password"
        ],

        "Insider Threat": [
            "employee",
            "insider",
            "staff member",
            "internal user"
        ],

        "Supply-Chain Compromise": [
            "third-party",
            "vendor",
            "software supplier",
            "compromised update"
        ]
    }

    for cause, keywords in causes.items():

        if any(word in description for word in keywords):

            return cause

    return "Unknown Root Cause"


print("SECURITY INCIDENT ROOT-CAUSE CLASSIFIER")

description = input("\nEnter incident description: ")

result = identify_root_cause(description)

print("\nIdentified Root Cause:", result)

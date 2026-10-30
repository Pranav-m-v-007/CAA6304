# Known attack signatures
attack_signatures = [
    "SQL Injection",
    "Port Scan",
    "Malicious Payload"
]

# Trusted IP addresses
whitelist = [
    "192.168.1.10",
    "192.168.1.20"
]

def check_traffic(ip, traffic):

    if ip in whitelist:
        return "ALLOWED - Trusted IP"

    for signature in attack_signatures:

        if signature.lower() in traffic.lower():
            return "BLOCKED - Malicious Traffic Detected"

    return "ALLOWED - Normal Traffic"


# Input network traffic
ip = input("Enter source IP address: ")
traffic = input("Enter traffic description: ")

result = check_traffic(ip, traffic)

print("\nIPS Decision:", result)

# Minimum required security baseline
baseline = {
    "MFA": True,
    "Firewall": True,
    "Antivirus": True,
    "Backup": True
}

# Current organization configuration
current = {}

print("Enter current security configuration (yes/no):")

for control in baseline:
    answer = input(control + ": ").lower()
    current[control] = (answer == "yes")

print("\nSecurity Compliance Report")

failed = []

for control, required in baseline.items():

    if current[control] == required:
        print(control, ": PASS")

    else:
        print(control, ": FAIL")
        failed.append(control)

print("\nSummary:")

if not failed:
    print("All security controls meet the baseline.")

else:
    print("Controls that need improvement:")
    for control in failed:
        print("-", control)

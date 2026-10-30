def identify_improvements(report):
    report = report.lower()

    improvements = {
        "Patch Management": ["patch", "software update", "security update"],
        "Security Awareness": ["training", "awareness", "employee education"],
        "Monitoring": ["monitoring", "logs", "alerts", "detection"],
        "Backup Strategy": ["backup", "recovery", "data restoration"],
        "Access Control": ["access control", "unauthorized access", "permissions"]
    }

    found = []

    for area, keywords in improvements.items():
        for keyword in keywords:
            if keyword in report:
                found.append(area)
                break

    return found


report = input("Enter post-incident report: ")

result = identify_improvements(report)

print("\nIdentified Improvement Areas:")

if result:
    for area in result:
        print("-", area)
else:
    print("No improvement areas found.")

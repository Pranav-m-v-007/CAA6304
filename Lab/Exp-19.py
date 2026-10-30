events = [
    {"user": "Ravi", "action": "Login"},
    {"user": "Arun", "action": "Failed Login"},
    {"user": "Ravi", "action": "Login"},
    {"user": "Arun", "action": "Failed Login"},
    {"user": "Kiran", "action": "Logout"}
]

# Search Filter
search = input("Enter action to search: ")

print("\nFiltered Events:")

filtered = []

for event in events:
    if search.lower() in event["action"].lower():
        filtered.append(event)
        print(event)

# Stats Count by Field
field = input("\nEnter field for statistics (user/action): ")

if field not in ["user", "action"]:
    print("Invalid field!")

else:
    counts = {}

    for event in events:
        value = event[field]
        counts[value] = counts.get(value, 0) + 1

    print("\nStats Count by", field)

    for key, value in counts.items():
        print(key, ":", value)

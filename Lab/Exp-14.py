# Raw Events from Multiple Sources

events = [

    {
        "source": "Firewall",
        "event": "Failed Login",
        "user": "admin"
    },

    {
        "source": "Server",
        "event": "Failed Login",
        "user": "admin"
    },

    {
        "source": "Antivirus",
        "event": "Malware Detected",
        "user": "user1"
    },

    {
        "source": "Firewall",
        "event": "Successful Login",
        "user": "admin"
    }
]


# STEP 1: COLLECTION

print("STEP 1: EVENT COLLECTION")

for event in events:
    print(event)


# STEP 2: NORMALIZATION

print("\nSTEP 2: EVENT NORMALIZATION")

normalized_events = []

for event in events:

    normalized = {

        "source": event["source"],
        "activity": event["event"],
        "username": event["user"]

    }

    normalized_events.append(normalized)

for event in normalized_events:
    print(event)


# STEP 3: CORRELATION

print("\nSTEP 3: EVENT CORRELATION")

failed_logins = {}

for event in normalized_events:

    if event["activity"] == "Failed Login":

        user = event["username"]

        failed_logins[user] = failed_logins.get(user, 0) + 1


# STEP 4: ALERT GENERATION

print("\nSTEP 4: SIEM ALERTS")

alert_found = False

for user, count in failed_logins.items():

    if count >= 2:

        print("ALERT: Multiple failed logins for", user)

        alert_found = True


for event in normalized_events:

    if event["activity"] == "Malware Detected":

        print("ALERT: Malware detected for", event["username"])

        alert_found = True


if not alert_found:

    print("No security threats detected.")


print("\nSIEM PIPELINE COMPLETED")

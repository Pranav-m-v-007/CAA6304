logs = [
    ("admin", "Failed"),
    ("admin", "Failed"),
    ("admin", "Failed"),
    ("admin", "Success"),
    ("user1", "Failed")
]

username = input("Enter username: ")

threshold = 3
failed_count = 0
detected = False

for user, status in logs:

    if user == username:

        if status == "Failed":
            failed_count += 1

        elif status == "Success":

            if failed_count >= threshold:
                detected = True

            failed_count = 0

if detected:
    print("Possible Brute-Force Attack Detected!")

elif failed_count >= threshold:
    print("Repeated Failed Login Attempts Detected!")

else:
    print("No Brute-Force Pattern Detected.")

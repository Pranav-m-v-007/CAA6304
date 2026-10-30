# Defense-in-Depth Simulation

security_layers = [

    "Firewall",
    "IDS",
    "Antivirus",
    "Access Control"
]


def check_attack(attack):

    print("\nDEFENSE-IN-DEPTH SECURITY MODEL")

    blocked = False

    for layer in security_layers:

        print("\nChecking:", layer)

        if attack == "malware" and layer == "Antivirus":

            print("Malware detected and blocked!")

            blocked = True

            break

        elif attack == "unauthorized" and layer == "Access Control":

            print("Unauthorized access blocked!")

            blocked = True

            break

        elif attack == "ddos" and layer == "Firewall":

            print("Attack detected and blocked by Firewall!")

            blocked = True

            break

        else:

            print("No threat detected.")

    if blocked:

        print("\nFINAL RESULT: System Protected")

    else:

        print("\nFINAL RESULT: Attack Passed Through Security Layers")


print("Available Attacks: malware, unauthorized, ddos, unknown")

attack = input("\nEnter attack type: ").lower()

check_attack(attack)

# Network Segmentation Access Policy Simulation

# Define network segments
segments = {
    "Low-Trust": ["192.168.1.10"],
    "Internal": ["192.168.2.10"],
    "Sensitive": ["192.168.3.10"]
}

# Define access policies
access_policy = {
    "Low-Trust": ["Internal"],
    "Internal": ["Sensitive"],
    "Sensitive": []
}

def check_access(source, destination):
    if destination in access_policy[source]:
        return "ACCESS GRANTED"
    else:
        return "ACCESS DENIED - Segmentation Blocked Access"

# Display network segments
print("Network Segments:")
for segment, devices in segments.items():
    print(segment, ":", devices)

# Simulate access attempts
print("\nAccess Attempts:")

attempts = [
    ("Low-Trust", "Internal"),
    ("Low-Trust", "Sensitive"),
    ("Internal", "Sensitive"),
    ("Sensitive", "Low-Trust")
]

for source, destination in attempts:
    print(source, "->", destination, ":", 
          check_access(source, destination))

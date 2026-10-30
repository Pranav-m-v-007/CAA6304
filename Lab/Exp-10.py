class StatefulFirewall:

    def __init__(self):
        self.connections = set()

    def process_packet(self, source, destination, direction):

        connection = (source, destination)

        if direction.upper() == "OUTBOUND":

            self.connections.add(connection)

            return "ALLOWED - Outbound Connection Established"

        elif direction.upper() == "INBOUND":

            reverse_connection = (destination, source)

            if reverse_connection in self.connections:

                return "ALLOWED - Return Traffic"

            else:

                return "BLOCKED - Unsolicited Inbound Traffic"

        else:
            return "INVALID DIRECTION"


firewall = StatefulFirewall()

print("STATEFUL INSPECTION FIREWALL")

print("\n1.", firewall.process_packet(
    "192.168.1.10", "8.8.8.8", "OUTBOUND"
))

print("\n2.", firewall.process_packet(
    "8.8.8.8", "192.168.1.10", "INBOUND"
))

print("\n3.", firewall.process_packet(
    "45.10.10.5", "192.168.1.10", "INBOUND"
))

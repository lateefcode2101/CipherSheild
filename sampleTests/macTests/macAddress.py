import uuid


def get_mac_address():
    mac = uuid.getnode()
    return ''.join(("%012X" % mac)[i:i + 2] for i in range(0, 12, 2))


mac_address = get_mac_address()
print("MAC Address:", mac_address)

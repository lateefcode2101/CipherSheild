import uuid


def generate_device_id():
    device_id = uuid.uuid4()
    device_id_without_hyphens = str(uuid.uuid4()).replace("-", "")
    return device_id


# Example usage
device_id = generate_device_id()
print("Generated Device ID:", device_id)
print("Generated device_id_without_hyphens ID:", device_id_without_hyphens)

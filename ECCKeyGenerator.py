import base64
import hashlib
import math
import os
import time
import uuid
from distutils.log import Log

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend


def get_mac_address():
    mac = uuid.getnode()
    return ''.join(("%012X" % mac)[i:i + 2] for i in range(0, 12, 2))


def get_vid():
    with open('content/Vid/VID.txt', "rb") as fwrite16:
        vid_data = fwrite16.read()
    return vid_data


def generate_x_coordinate():
    """
generates x_coordinate using encoded system time, process id, and machine id
    :return: x_coordinate
    """
    # Collect system-specific information
    system_time = str(time.time()).encode()  # Current system time
    process_id = str(os.getpid()).encode()  # Process ID
    machine_id = str(uuid.uuid4()).replace("-", "").encode()  # Machine ID (example: user ID)

    # Concatenate and hash the collected information
    data_to_hash = b''.join([system_time, process_id, machine_id])
    hashed_data = hashlib.sha256(data_to_hash).digest()

    # Convert the hash to an integer for use as the x-coordinate
    x_coordinate = int.from_bytes(hashed_data, byteorder='big')

    return x_coordinate


# Generate ECC key pair
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()

# Custom ECC Equation Constants
a = int.from_bytes(get_vid(), 'big')  # Coefficient 'a' in the equation y^2 = x^3 + a*x + b
b = int.from_bytes(get_mac_address().encode(), 'big')  # Coefficient 'b' in the equation y^2 = x^3 + a*x + b


def ecc_generate_key():
    # Compute the x coordinate from the shared secret
    x = generate_x_coordinate()

    # Compute the RHS of the ECC equation
    rhs = x ** 3 + a * x + b

    # Compute the square root of the RHS
    y = int(math.sqrt(rhs))

    return y


def int_to_base64(integer):
    """
    :param integer: takes in integer values
    :return: returns base64 encoded string
    """
    # Convert integer to bytes
    integer_bytes = integer.to_bytes((integer.bit_length() + 7) // 8, byteorder='big')
    # Encode bytes to Base64
    base64_encoded = base64.b64encode(integer_bytes)
    return base64_encoded


def base64_to_int(base64_encoded):
    # Decode Base64 to bytes
    decoded_bytes = base64.b64decode(base64_encoded)
    # Convert bytes to integer
    decoded_integer = int.from_bytes(decoded_bytes, byteorder='big')
    return decoded_integer


# Perform ECDH key exchange to obtain the shared secret
# shared_secret = private_key.exchange(ec.ECDH(), public_key)

# Generate ECC-based key using the shared secret
ecc_key = ecc_generate_key()

print("ECC number Key:", ecc_key)
print("type of ecc key", type(ecc_key))
# Convert ECC key to Base64 and back to integer
int2b64 = int_to_base64(ecc_key)
print("ECC int_to_base64 is ", int2b64)
print("ECC base64_to_int is ", base64_to_int(int2b64))

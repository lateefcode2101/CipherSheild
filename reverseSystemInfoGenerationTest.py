import base64
from datetime import datetime
import hashlib
import os
import time
import uuid


def generate_custom_timestamp():
    # Get the current date and time
    current_time = datetime.now()

    # Format the current date and time in the desired format:
    # ddmmyyyyhh24miss: Day, Month, Year, Hour (24-hour format), Minutes, Seconds
    # Milliseconds: using `%f` which includes microseconds; we'll convert it to milliseconds by slicing
    timestamp = current_time.strftime("%d%m%Y%H%M%S") + str(current_time.microsecond)[:3]

    return timestamp


def reverse_generate_b_from_system_specific_data(x_coordinate):
    # Convert the integer back to bytes
    system_Data = x_coordinate.to_bytes((x_coordinate.bit_length() + 7) // 8, byteorder='big')

    # Since system time is fixed at 17 bytes, extract it directly
    system_time = system_Data[:17]

    # Since machine ID is fixed at 32 bytes, extract it directly from the end
    machine_id = system_Data[-32:]

    # The remaining data between system time and machine ID is the process ID
    process_id = system_Data[17:-32]

    # Decode the data from bytes to readable forms
    system_time_decoded = system_time.decode()
    process_id_decoded = process_id.decode()
    machine_id_hex = machine_id.decode()
    # Print the reconstructed system-specific data (just for demonstration)
    print('Reconstructed system time:', system_time_decoded)
    print('Reconstructed process ID:', process_id_decoded)
    print('Reconstructed machine ID:', machine_id_hex)


def base64_to_int(base64_string):

    # Decode the base64 encoded string to bytes
    decoded_bytes = base64.b64decode(base64_string)

    # Convert the bytes object to an integer
    integer_value = int.from_bytes(decoded_bytes, byteorder='big')

    return integer_value

reverse_generate_b_from_system_specific_data(8326124401404354131708027748732096900992831707723917205182374761634022670964616303855773623187593969173016677072541652266070326)
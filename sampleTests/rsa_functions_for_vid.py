from math import gcd

from Crypto.Random import random
from sympy import totient


def text_to_number(text):
    if isinstance(text, int):
        return text
    # Convert each character to its numeric value and concatenate them
    return int(''.join(format(ord(char), '03') for char in str(text)))


def number_to_text(number):
    # Convert the number to text by converting each triplet of digits back to characters
    num_str = str(number)
    # Ensure that the length of the numeric representation is a multiple of 3
    if len(num_str) % 3 != 0:
        num_str = '0' * (3 - len(num_str) % 3) + num_str  # Pad with '0' if necessary
    # Convert each triplet of digits back to characters
    return ''.join(chr(int(num_str[i:i + 3])) for i in range(0, len(num_str), 3))


def generate_key_pair(secret_text):
    # Convert the secret text to a numeric value
    n = text_to_number(secret_text)
    print("Generated n value:", n)  # Print the generated n value

    # Choose a suitable e such that 1 < e < ϕ(n) and e is coprime with ϕ(n)
    phi_n = int(totient(n))
    e = random.randint(2, phi_n - 1)
    while gcd(e, phi_n) != 1:
        e = random.randint(2, phi_n - 1)

    # Find d such that d is the modular multiplicative inverse of e modulo ϕ(n)
    d = pow(e, -1, phi_n)

    # Public key consists of (n, e), private key consists of (n, d)
    public_key = (n, e)
    private_key = (n, d)

    return public_key, private_key


def encrypt(message, public_key):
    n, e = public_key
    encrypted_message = pow(message, e, n)
    return encrypted_message


def decrypt(encrypted_message, private_key):
    n, d = private_key
    decrypted_message = pow(encrypted_message, d, n)
    return decrypted_message


with open('VID.txt', 'rb') as f:
    Vid_data = f.read()
secret_text = Vid_data
# Generate key pair using the secret text
public_key, private_key = generate_key_pair(secret_text)
print("Public Key:", public_key)
print("Private Key:", private_key)

# Encrypt a message
message = text_to_number("Hello, how are you!")
print("Numeric representation of the message:", message)
encrypted_message = encrypt(message, public_key)
print("Encrypted message:", encrypted_message)

print("Message is ", message)
# Decrypt the message
decrypted_message_numeric = decrypt(encrypted_message, private_key)
print("Decrypted message (numeric representation):", decrypted_message_numeric)
decrypted_message = number_to_text(decrypted_message_numeric)
print("Decrypted message (text):", decrypted_message)

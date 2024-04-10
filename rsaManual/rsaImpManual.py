import random

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def mod_inverse(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

def encrypt(public_key, plaintext):
    e, n = public_key
    cipher = [pow(ord(char), e, n) for char in plaintext]
    return cipher

if __name__ == '__main__':
    # Choose prime numbers p and q
    p = 61
    q = 53
    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose public key exponent e
    e = 17

    # Calculate private key exponent d
    d = mod_inverse(e, phi)

    # Public key
    public_key = (e, n)
    print("Public Key:", public_key)

    # Private key
    private_key = (d, n)
    print("Private Key:", private_key)

    # Original message
    message = "Hello, World!"
    print("Original Message:", message)

    # Encrypt the message using the public key
    encrypted_message = encrypt(public_key, message)
    print("Encrypted Message:", encrypted_message)

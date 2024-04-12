import base64
import random

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers, RSAPublicNumbers
import random
from sympy import isprime

p = None
q = None
# Define the paths to public and private keys
public_key_path = 'keys/pubKey/public_key.pem'
private_key_path = 'keys/privKey/private_key.pem'


def generate_prime(bit_length):
    """
    Generate a prime number with the given bit length.
    """
    while True:
        # Generate a random number of the specified bit length
        prime_candidate = random.getrandbits(bit_length)

        # Adjust the prime candidate to the full bit length if necessary
        prime_candidate |= (1 << bit_length - 1)  # Ensure the number has the full bit length

        # Ensure the prime candidate is odd (avoid even numbers except 2)
        prime_candidate |= 1

        # Check if the generated number is prime
        # `isprime` from sympy provides an optimized primality test
        if isprime(prime_candidate):
            return prime_candidate


def is_prime(num):
    if num <= 1:
        return False
    if num <= 3:
        return True
    if num % 2 == 0 or num % 3 == 0:
        return False
    i = 5
    while i * i <= num:
        if num % i == 0 or num % (i + 2) == 0:
            return False
        i += 6
    return True


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1


def generate_keys(bit_length):
    global p, q
    p = generate_prime(
        bit_length)
    # generate_prime(bit_length // 2)
    q = generate_prime(
        bit_length)
    # generate_prime(bit_length // 2)
    print('len of p is ', p.bit_length())
    print('len of q is ', q.bit_length())
    print('Type is ', type(p))
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537  # Chosen public exponent

    # Ensure e and phi are coprime
    while gcd(e, phi) != 1:
        e = random.randint(3, phi)

    d = mod_inverse(e, phi)
    with open('PrimesData.txt', 'w') as file:
        file.write("p= ")
        file.write(str(p))
        file.write("\n")
        file.write("Q= ")
        file.write(str(q))
        file.write("\n")
        file.write("n= ")
        file.write(str(n))
        file.write("\n")
        file.write("e= ")
        file.write(str(e))
        file.write("\n")
        file.write("d= ")
        file.write(str(d))
        file.write("\n")
    return n, e, d


def rsa_components_to_pem(n, e, d):
    global p, q
    dmp1 = d % (p - 1)
    dmq1 = d % (q - 1)
    iqmp = mod_inverse(q, p)
    # Constructing RSA key objects from the given components
    public_numbers = RSAPublicNumbers(e, n)
    private_numbers = RSAPrivateNumbers(
        public_numbers=public_numbers,
        p=p,
        q=q,
        d=d,
        dmp1=dmp1,  # We also need the RSA CRT coefficients (dmp1, dmq1, iqmp)
        dmq1=dmq1,
        iqmp=iqmp
    )

    # Create RSA public and private key objects
    private_key = private_numbers.private_key(default_backend())
    public_key = public_numbers.public_key(default_backend())

    # Serialize private key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    # print('private_key_pem is ',private_key_pem)

    # Serialize public key to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    # print('public key pem is ',public_key_pem)

    return private_key_pem, public_key_pem


def write_keys_to_files(private_key_pem, public_key_pem, private_key_filename=private_key_path,
                        public_key_filename=public_key_path):
    # Write the private key to a file
    with open(private_key_filename, 'w') as private_key_file:
        private_key_file.write(private_key_pem)

    # Write the public key to a file
    with open(public_key_filename, 'w') as public_key_file:
        public_key_file.write(public_key_pem)


# Example usage:
bit_length = 2048  # Key size in bits
n, e, d = generate_keys(bit_length)
private_key_pem, public_key_pem = rsa_components_to_pem(n, e, d)
print("RSA Private Key (PEM format):")
print(private_key_pem)
print("\nRSA Public Key (PEM format):")
print(public_key_pem)
write_keys_to_files(private_key_pem, public_key_pem)
print('Keys written to files\n')
with open('public_key.pem', 'rb') as f:
    public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
with open('private_key.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
print('keys read successfully')

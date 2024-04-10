from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def generate_rsa_keys(p, q, exp, key_size=2048):
    # Convert primes and exponent to integers
    p = int(p)
    q = int(q)
    exp = int(exp)

    # Calculate modulus (n) and private exponent (d)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    d = pow(exp, -1, phi_n)

    # Generate RSA private key
    private_key = rsa.RSAPrivateKey(
        modulus=n,
        exponent=exp,
        d=d,
        p=p,
        q=q,
        public_exponent=exp,
        private_exponent=d,
        backend=default_backend()
    )

    # Serialize private key to PEM format
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key to PEM format
    pem_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_private, pem_public

# Input prime numbers and public exponent
p = input("Enter prime p: ")
q = input("Enter prime q: ")
exp = input("Enter public exponent: ")

# Generate RSA keys
private_key_pem, public_key_pem = generate_rsa_keys(p, q, exp)

# Write keys to files
with open('private_key.pem', 'wb') as f:
    f.write(private_key_pem)

with open('public_key.pem', 'wb') as f:
    f.write(public_key_pem)

print("Private and public keys generated and saved in PEM format.")

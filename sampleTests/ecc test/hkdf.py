import hmac
import hashlib

def hkdf_extract(salt, input_key_material):
    return hmac.new(salt, input_key_material, hashlib.sha256).digest()

def hkdf_expand(prk, length):
    t = b""
    okm = b""
    print("(length + 255) // 256= ",(length + 255) // 256)
    for i in range((length + 255) // 256):
        t = hmac.new(prk, t  + bytes([i + 1]), hashlib.sha256).digest()
        okm += t
    return okm[:length]

# Example usage:
# Assuming you have the y_squared value from your ECC equation
y_squared = b"\x12\x34\x56\x78\x90\xAB\xCD\xEF"  # Example value, replace with actual value
salt = b""  # Salt (optional)
info = b"Encryption Key"  # Additional info (optional)
length = 64  # Length of the derived key in bytes

# Extract
prk = hkdf_extract(salt, y_squared)

# Expand
encryption_key = hkdf_expand(prk, length)

print("Derived Encryption Key:", encryption_key.hex())

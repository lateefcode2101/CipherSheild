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

def decrypt(private_key, ciphertext):
    d, n = private_key
    decrypted_nums = [pow(char, d, n) for char in ciphertext]
    decrypted_message = ''.join([chr(x) for x in decrypted_nums])
    return decrypted_message

if __name__ == '__main__':
    # Set private key components d and n
    d = 2753
    n = 3233

    # Provide the ciphertext as a list of integers
    ciphertext = [3000, 1313, 745, 745, 2185, 678, 1992, 604, 2185, 2412, 745, 1773, 1853]
    # Decrypt the message
    decrypted_message = decrypt((d, n), ciphertext)
    print("Decrypted Message:", decrypted_message)

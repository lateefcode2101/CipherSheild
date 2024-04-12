import random
import sympy
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_prime(size):
    """
    Generate a prime number of given size.
    """
    while True:
        num = random.getrandbits(size)
        num |= 1  # Ensure it's odd
        if sympy.isprime(num):
            return num


def generate_rsa_keys():
    # Generate secure prime numbers p and q
    p = 17245690088095257483684823354964276774903780028833218598971938922695834036838533214123963011261791993009999431803740944573922741097848888793695853093324705491367306351649651580592683504377625050103491493882900791175111012111285187249530750176095578558290439680782802553096953904577005168231911893341667104237854981440039768615492348452304896234424460388421464643680483899443254282636392339307652476780029873802146968402352283493332752485712683739093288797657112312226233171636746826089066317802139224781098290387433646046730097556681478919206532658464662550520186987517371879039938708666830152892841690923066662475013
    q = 3874345050496419991164298581649837170438890556495987041462021036102690664333110893590463594807672697536629673272207087329682261578086029206513958506311068515422481796199899154177412145771180064143930131143371331861967723459481988365603609674597417214684292769371401968236895394240777162540131820435602392970999123550613159114052569889389631196279354358322691796596446450733806596502061341018266138684250433305962322433262555543285257000759130525150603858286488706500270173641692429399934283628312472977340422646181862077823048047102947413670715880700284404813597388855034223782117870224997403616877405939076195972959

    # Calculate modulus (n)
    n = p * q

    # Calculate Euler's totient function φ(n)
    phi_n = (p - 1) * (q - 1)

    # Choose a suitable public exponent (e)
    e = 65537  # Common choice for e
    while sympy.gcd(e, phi_n) != 1:
        e += 2  # Ensure e is odd and try the next value

    # Calculate private exponent (d)
    d = pow(e, -1, phi_n)

    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Extract public key components
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    e_extracted = public_numbers.e
    n_extracted = public_numbers.n
    private_numbers = private_key.private_numbers()
    p_extracted = private_numbers.p
    q_extracted = private_numbers.q
    d_extracted = private_numbers.d
    print(" p:", p_extracted)
    print(" q:", q_extracted)
    print(" d:", d_extracted)

    return p, q, e, d, n, e_extracted, n_extracted, private_key, public_key


# Generate RSA keys
p, q, e, d, n, e_extracted, n_extracted, private_key, public_key = generate_rsa_keys()

# Serialize private key to PEM format
pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Serialize public key to PEM format
pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Write private key to file
with open('private_key.pem', 'wb') as f:
    f.write(pem_private)

# Write public key to file
with open('public_key.pem', 'wb') as f:
    f.write(pem_public)

# print("Prime p:", p)
# print("Prime q:", q)
# print("Public exponent e:", e)
# print("Private exponent d:", d)
# print("Modulus n:", n)
print(" e:", e_extracted)
print(" n:", n_extracted)
print("Private and public keys generated and saved in PEM format.")

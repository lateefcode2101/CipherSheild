# Generate RSA private key with specified prime numbers and public exponent
openssl genpkey -algorithm RSA \
                -pkeyopt rsa_keygen_bits:2048 \
                -pkeyopt rsa_keygen_pubexp:65537 \
                -pkeyopt rsa_keygen_p:1234567890123457 \
                -pkeyopt rsa_keygen_q:9876543210987651 \
                -out private_key.pem

# Extract public key from private key
openssl rsa -in private_key.pem -outform PEM -pubout -out public_key.pem

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generar un par de claves RSA (clave pública y clave privada)
def generate_rsa_keys():
    # Generar una clave privada
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  # Tamaño de la clave, 2048 bits es común
    )

    # Generar la clave pública correspondiente a la clave privada
    public_key = private_key.public_key()

    return private_key, public_key

# Guardar la clave privada en un archivo PEM
def save_private_key(private_key, filename):
    with open(filename, "wb") as private_key_file:
        private_key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

# Guardar la clave pública en un archivo PEM
def save_public_key(public_key, filename):
    with open(filename, "wb") as public_key_file:
        public_key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

# Generar las claves
private_key, public_key = generate_rsa_keys()

# Guardar las claves en archivos
save_private_key(private_key, "private_key.pem")
save_public_key(public_key, "public_key.pem")

print("Las claves han sido generadas y guardadas.")

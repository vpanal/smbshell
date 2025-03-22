# SMB Shell

SMB Shell is a tool designed to handle communications between an attacker and a victim through an external SMB server connection, allowing to stabilize an interactive terminal in an encrypted manner.

## Features

- Sending and receiving commands and responses via SMB.
- Data encryption with AES and RSA.
- Dynamic generation of public and private keys.
- Remote execution of encrypted commands.
- Secure bidirectional communication between client and server.

## Installation

```bash
git clone https://github.com/vpanal/smbshell.git
cd smbshell
pip install -r requirements.txt
```

## Compiling client.py

```bash
# Without obfuscation
pyinstaller --onefile --hidden-import cryptography.hazmat.primitives ./client.py

# Obfuscated compilation
pyarmor gen ./client.py
cd dist
pyinstaller --onefile --add-data "pyarmor_runtime_000000;pyarmor_runtime_000000" --hidden-import cryptography.hazmat.primitives --hidden-import cryptography.hazmat.primitives.serialization --hidden-import smb --hidden-import smb.SMBConnection --hidden-import cryptography.hazmat.primitives.padding client.py
```

## Configuration

The internal parameters of the client.py and server.py files must be modified for the correct configuration of the SMB server and response times.

## Usage

### Basic example:

1. Start the server by running `server.py`:

```bash
python server.py
```

2. Start the client by running `client.py`:

```bash
python client.py
```

### Server commands

- **`help`**: Displays a list of available commands.
- **`quit`**: Closes the attacker's session.
- **`exit`**: Ends the connection with the client.
- Send a command: Type any valid shell command to execute it on the client.

### Notes

- Temporary files are generated to handle keys and data, and are automatically deleted after use.
- If you want to close the client's session, use the `exit` command.

## Demo

### Execution flow

Below is the default execution flow of the application.

```mermaid
sequenceDiagram
client.py -->> SMB: Check if a.pub exists.
Note right of client.py: Check every seconds indicated by sleep_time <br/> variable until the process ends or the file is found.
Note left of server.py: Generate private and public key if doesn't exists. <br/>
server.py->> SMB: Upload to.pub
SMB->>client.py: Download and delete a.pub
Note right of client.py: 1. Generate symmetric password random. <br/> 2. Encrypt symmetric password with a.pub. <br/>
client.py->> SMB: Upload pass.txt
SMB->>server.py: Download and delete pass.txt
Note left of server.py: Decrypt symmetric password with private key. <br/>
client.py -->> SMB: Check if command.txt exists.
Note right of client.py: Check every seconds indicated in the sleep_time <br/> variable until the process ends or the file is found.
Note left of server.py: Request command and encrypt with symmetric password.
server.py->> SMB: Upload command.txt
SMB->>client.py: Download and delete command.txt
Note right of client.py: Decrypt with symmetric password and run command.
server.py -->> SMB: Check if result.txt exists.
Note left of server.py: Check every seconds indicated by sleep_time <br/> variable 2 times or until the file is found.
Note right of client.py: 1. Runs the command and kill it if it takes longer <br/> than indicated by timeout_time variable. <br/> 2. Encrypts the response with symmetric password.
client.py->> SMB: Upload result.txt
SMB->>server.py: Download and delete result.txt
Note left of server.py: Decrypt with symmetric password and show result.
Note right of client.py: Return to check step.
client.py -->> SMB: Check if command.txt exists.
```

### Usage demonstration

<p align="left"><img width=100% alt="Usage demonstration" src="https://github.com/vpanal/smbshell/blob/main/assets/demo.gif"></p>

## Security notes

This script is designed for educational purposes and testing in controlled environments only. **Do not use it on systems without explicit authorization.**

## Contributions

If you want to contribute, fork the repository, make your changes, and send a pull request.

## License

This project is under the MIT License. See the `LICENSE` file for more details.

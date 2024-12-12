import socket
import ssl
import threading
import hashlib
import psycopg2
import bcrypt
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

HOST = "0.0.0.0"  
PORT = 6223
CERTFILE = "cert.pem"
KEYFILE = "key.pem"
BUFFER_SIZE = 4096
MASTER_PEM = "master.pem"
CONFIG_FILE = "db_conf.json"
AES_KEY_FILE = "enkey.pem"

def load_aes_key():
    """Loads the AES key from a file."""
    try:
        with open(AES_KEY_FILE, "rb") as f:
            key = f.read()
            if len(key) != 32:  # AES-256 requires a 32-byte key
                raise ValueError("Invalid AES key size. Key must be 32 bytes.")
            return key
    except FileNotFoundError:
        print(f"Error: AES key file '{AES_KEY_FILE}' not found.")
        return None

def encrypt_data(data, key):
    """Encrypt data using AES-256."""
    iv = os.urandom(16)  # Generate a random initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode("utf-8")) + encryptor.finalize()
    return iv + ciphertext  # Prepend IV to the ciphertext for later decryption

def decrypt_data(encrypted_data, key):
    """Decrypt data using AES-256."""
    iv = encrypted_data[:16]  # Extract the IV
    ciphertext = encrypted_data[16:]  # Extract the ciphertext
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_data.decode("utf-8")

def load_db_config():
    """Loades the db config"""
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: Config file '{CONFIG_FILE}' not found")
        return None
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse JSON in '{CONFIG_FILE}': {e}")
        return None

def create_tls_context():
    """Creates a TLS context."""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)
    return context

def generate_hash(identifier):
    """Generates a hash of the identifier"""
    try:
        with open(MASTER_PEM, "rb") as f:
            master_data = f.read()
        combined = master_data + identifier.encode("utf-8")
        hashed = hashlib.sha256(combined).hexdigest()
        return hashed
    except FileNotFoundError:
        print("Error: master file not found.")
        return None

def connect_to_db():
    """Connects to the db"""
    db_config = load_db_config()
    if not db_config:
        return None
    try:
        conn = psycopg2.connect(**db_config)
        return conn
    except psycopg2.Error as e:
        print(f"Database connection error: {e}")
        return None

def handle_get(username):
    """Handles the GET request to fetch IP and port of a user."""
    conn = connect_to_db()
    if not conn:
        return "ERROR: Database connection failedEOF"

    aes_key = load_aes_key()
    if not aes_key:
        return "ERROR: Server encryption key missingEOF"

    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT ip, port FROM users WHERE username = %s",
                (username,)
            )
            result = cur.fetchone()

            if not result:
                return f"GET-RESPONSE INVALID username: {username}"

            encrypted_ip, encrypted_port = result

            decrypted_ip = decrypt_data(encrypted_ip, aes_key)
            decrypted_port = decrypt_data(encrypted_port, aes_key)

            return f"GET-RESPONSE VALID {username} {decrypted_ip} {decrypted_port}"
    except psycopg2.Error as e:
        print(f"Database query error: {e}")
        return "ERROR: Database query failedEOF"
    finally:
        conn.close()

def handle_login(username, password, hashed_identifier):
    """Handles the login endpoint"""
    conn = connect_to_db()
    if not conn:
        return "ERROR: Database connection failed"

    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT password, identifier FROM users WHERE username = %s",
                (username,)
            )
            result = cur.fetchone()
            if not result:
                return "ERROR: User not found"

            stored_password, stored_identifier = result

            if not bcrypt.checkpw(password.encode("utf-8"), stored_password.encode("utf-8")):
                return "ERROR: Invalid credentials"

            if stored_identifier != hashed_identifier:
                return "ERROR: Invalid credentials"

            return "Login successful"
    except psycopg2.Error as e:
        print(f"Database query error: {e}")
        return "ERROR: Database query failed"
    finally:
        conn.close()

def handle_register(username, password, hashed_identifier, ip, port):
    """Handles the registration endpoint."""
    conn = connect_to_db()
    if not conn:
        return "ERROR: Database connection failed"
    
    aes_key = load_aes_key()
    if not aes_key:
        return "ERROR: Server encryption key missing"

    try:
        encrypted_ip = encrypt_data(ip, aes_key)
        encrypted_port = encrypt_data(port, aes_key)

        with conn.cursor() as cur:
            cur.execute(
                "SELECT username FROM users WHERE username = %s OR identifier = %s",
                (username, hashed_identifier)
            )
            result = cur.fetchone()
            if result:
                return "ERROR: Username or identifier already exists"

            hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

            cur.execute(
                "INSERT INTO users (username, password, identifier, ip, port) VALUES (%s, %s, %s, %s, %s)",
                (username, hashed_password.decode("utf-8"), hashed_identifier, encrypted_ip, encrypted_port)
            )
            conn.commit()
            return "Register successful"
    except psycopg2.IntegrityError as e:
        print(f"Database integrity error: {e}")
        return "ERROR: Failed to register due to database constraints"
    except psycopg2.Error as e:
        print(f"Database query error: {e}")
        return "ERROR: Database query failed"
    finally:
        conn.close()

def handle_initiate(username, recipiant_ip, recipiant_port):
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((recipiant_ip, recipiant_port), timeout=30) as sock:
            with context.wrap_socket(sock, server_hostname=recipiant_ip) as secure_socket:
                print(f"[INITIATE] Connection established with {recipiant_ip}")
                data = secure_socket.recv(BUFFER_SIZE).decode("utf-8")
                print(f"Payload received: {data}")

                return data
    except (socket.error, ssl.SSLError) as e:
        print(f"[ERROR] An error occurred: {e}")
        return None

def handle_client(conn, addr):
    """Handles an incoming client connection."""
    try:
        print(f"Connection established with {addr}")

        data = conn.recv(BUFFER_SIZE).decode("utf-8").strip()

        if not data:
            response = "ERROR: No data receivedEOF"
            conn.sendall(response.encode("utf-8"))
            return

        print(f"Chunk: {data}")

        parts = data.split()
        if len(parts) != 6:
            response = "ERROR: Invalid payload formatEOF"
            conn.sendall(response.encode("utf-8"))
            return

        endpoint = parts[0].upper()

        if endpoint == "GET":
            username = parts[1]
            response = handle_get(username)
        elif endpoint == "INITIATE":
            username = parts[1]
            recipiant_ip = parts[4]
            recipiant_port = parts[5]
            response = handle_initiate(username, recipiant_ip, recipiant_port)
        elif endpoint == "LOGIN":
            if len(parts) != 6:
                response = "ERROR: Invalid LOGIN payload formatEOF"
            else:
                _, username, password, identifier, ip, port = parts
                hashed_identifier = generate_hash(identifier)
                if not hashed_identifier:
                    response = "ERROR: Server configuration issueEOF"
                else:
                    response = handle_login(username, password, hashed_identifier) + "EOF"
        elif endpoint == "REGISTER":
            if len(parts) != 6:
                response = "ERROR: Invalid REGISTER payload formatEOF"
            else:
                _, username, password, identifier, ip, port = parts
                hashed_identifier = generate_hash(identifier)
                if not hashed_identifier:
                    response = "ERROR: Server configuration issueEOF"
                else:
                    response = handle_register(username, password, hashed_identifier, ip, port) + "EOF"
        else:
            response = "ERROR: Unknown endpointEOF"

        conn.sendall(response.encode("utf-8"))
        print(f"Response sent to {addr}: {response}")
    except ssl.SSLError as e:
        print(f"SSL error with {addr}: {e}")
    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except Exception as e:
            print(f"Error shutting down connection with {addr}: {e}")
        finally:
            conn.close()
            print(f"Connection with {addr} closed.")
  
def start_server():
    """Starts the server."""
    context = create_tls_context()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"Server listening on {HOST}:{PORT}")
        with context.wrap_socket(server_socket, server_side=True) as secure_socket:
            while True:
                try:
                    conn, addr = secure_socket.accept()
                    threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
                except ssl.SSLError as e:
                    print(f"SSL error: {e}")
                except Exception as e:
                    print(f"Error: {e}")

if __name__ == "__main__":
    start_server()
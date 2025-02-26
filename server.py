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
                    

            return "Login successful"
    except psycopg2.Error as e:
        print(f"Database query error: {e}")
        return "ERROR: Database query failed"
    finally:
        conn.close()

def handle_register(username, password, hashed_identifier, ip, port, settings):
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
                "INSERT INTO users (username, password, identifier, ip, port, settings) VALUES (%s, %s, %s, %s, %s, %s)",
                (username, hashed_password.decode("utf-8"), hashed_identifier, encrypted_ip, encrypted_port, settings)
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

def handle_get_settings(username):
    """Fetches the settings JSONB column for a user in the database."""
    conn = connect_to_db()
    if not conn:
        return "ERROR: Database connection failedEOF"

    try:
        with conn.cursor() as cur:
            cur.execute("SELECT settings FROM users WHERE username = %s", (username,))
            result = cur.fetchone()

            if not result or result[0] is None:
                return "ERROR: No settings foundEOF"

            return f"GET-SETTINGS SUCCESS {json.dumps(result[0])}"
    except psycopg2.Error as e:
        print(f"Database query error: {e}")
        return "ERROR: Database query failedEOF"
    finally:
        conn.close()

def handle_update_settings(username, settings):
    """Updates the settings for a user in the database."""
    conn = connect_to_db()
    if not conn:
        return "Error: db connection dailed"

    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET settings = %s WHERE username = %s",
                (json.dumps(settings), username)
            )
            conn.commit()

            if cur.rowcount == 0:
                return "ERROR: user not found"

            return "UPDATE-SETTINGS success"
    except json.JSONDecodeError:
            return "ERROR: invalid JSON format"
    except psycopg2.Error as e:
        return "ERROR: Database query fail"
    finally:
        conn.close()

def handle_list_friends(username):
    """Returns a list of friends."""
    conn = connect_to_db()
    if not conn:
        return "ERROR: Database connection failed"

    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT user1, user2 FROM friends WHERE (user1 = %s OR user2 = %s) AND status = 'accepted'",
                (username, username)
            )
            friends = cur.fetchall()

            if not friends:
                return "LIST-FRIENDS EMPTY"

            friend_list = [user[0] if user[0] != username else user[1] for user in friends]
            return f"LIST-FRIENDS SUCCESS {json.dumps(friend_list)}EOF"
    except psycopg2.Error as e:
        print(f"Database query error: {e}")
        return "ERROR: Database query failed"
    finally:
        conn.close()

def handle_remove_friend(username, friend_username):
    """Handles removing a friend."""
    conn = connect_to_db()
    if not conn:
        return "ERROR: Database connection failed"

    try:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM friends WHERE (user1 = %s AND user2 = %s) OR (user1 = %s AND user2 = %s) AND status = 'accepted'",
                (username, friend_username, friend_username, username)
            )
            if cur.rowcount == 0:
                return "ERROR: No existing friendship found"

            conn.commit()
            return "REMOVE-FRIEND SUCCESS"
    except psycopg2.Error as e:
        print(f"Database query error: {e}")
        return "ERROR: Database query failed"
    finally:
        conn.close()

def handle_accept_friend(username, friend_username):
    """Handles accepting a friend request."""
    conn = connect_to_db()
    if not conn:
        return "ERROR: Database connection failed"

    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE friends SET status = 'accepted' WHERE user1 = %s AND user2 = %s AND status = 'pending'",
                (friend_username, username)
            )
            if cur.rowcount == 0:
                return "ERROR: No pending friend request found"

            conn.commit()
            return "ACCEPT-FRIEND SUCCESS"
    except psycopg2.Error as e:
        print(f"Database query error: {e}")
        return "ERROR: Database query failed"
    finally:
        conn.close()

def handle_send_friend(username, friend_username):
    """Handles sending a friend request."""
    conn = connect_to_db()
    if not conn:
        return "ERROR: Database connection failed"

    try:
        with conn.cursor() as cur:
            # check if the users exist
            cur.execute("SELECT username FROM users WHERE username = %s", (friend_username,))
            if not cur.fetchone():
                return "ERROR: User does not exist"

            # check if a friendship already exists
            cur.execute(
                "SELECT status FROM friends WHERE (user1 = %s AND user2 = %s) OR (user1 = %s AND user2 = %s)",
                (username, friend_username, friend_username, username)
            )
            result = cur.fetchone()

            if result:
                return "ERROR: Friendship already exists or pending"

            # insert new friend request
            cur.execute("INSERT INTO friends (user1, user2, status) VALUES (%s, %s, 'pending')",
                        (username, friend_username))
            conn.commit()
            return "SEND-FRIEND SUCCESS"
    except psycopg2.Error as e:
        print(f"Database query error: {e}")
        return "ERROR: Database query failed"
    finally:
        conn.close()

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
            print(f"length of parts: {len(parts)}")
            if len(parts) < 6:
                response = "ERROR: Invalid LOGIN payload formatEOF"
            else:
                _, username, password, identifier, ip, port, *extra = parts
                hashed_identifier = generate_hash(identifier)
                if not hashed_identifier:
                    response = "ERROR: Server configuration issueEOF"
                else:
                    response = handle_login(username, password, hashed_identifier) + "EOF"
        elif endpoint == "REGISTER":
            if len(parts) < 6:
                response = "ERROR: Invalid REGISTER payload formatEOF"
            else:
                _, username, password, identifier, ip, port, *extra = parts
                settings_raw = "".join(extra)
                try:
                    settings_json = json.loads(settings_raw)
                except json.JSONDecodeError:
                    response = "Error: json is bad"
                hashed_identifier = generate_hash(identifier)
                if not hashed_identifier:
                    response = "ERROR: Server configuration issueEOF"
                else:
                    response = handle_register(username, password, hashed_identifier, ip, port, json.dumps(settings_json)) + "EOF"
        elif endpoint == "GET-SETTINGS":
            username = parts[1]
            response = handle_get_settings(username)
        elif endpoint == "UPDATE-SETTINGS":
            if len(parts) < 3:
                response = "Error: invalid update settings packet format"
            else:
                _, username, _, _, _, _, *extra = parts
                settings_raw = "".join(extra)
                settings_fixed = settings_raw.strip('"')
                settings_fixed = settings_fixed.replace("'", "\"")
                try:
                    settings_json = json.loads(settings_fixed)
                    print(settings_json)
                    response = handle_update_settings(username, settings_json)
                except json.JSONDecodeError:
                    response = "Error: json is bad"
        else:
            response = "ERROR: Unknown error/invalid packet format"

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
    context.load_cert_chain(certfile=CERTFILE,
                            keyfile=KEYFILE)
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

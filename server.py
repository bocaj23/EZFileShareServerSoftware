import socket
import ssl
import threading
import hashlib
import psycopg2
import bcrypt
import json

HOST = "0.0.0.0"  
PORT = 6223
CERTFILE = "cert.pem"
KEYFILE = "key.pem"
BUFFER_SIZE = 4096
MASTER_PEM = "master.pem"
CONFIG_FILE = "db_conf.json"

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


def handle_register(username, password, hashed_identifier):
    """Handles the registration endpoint"""
    conn = connect_to_db()
    if not conn:
        return "ERROR: Database connection failed"

    try:
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
                "INSERT INTO users (username, password, identifier) VALUES (%s, %s, %s)",
                (username, hashed_password.decode("utf-8"), hashed_identifier)
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

def handle_client(conn, addr):
    """Handles an incoming client connection."""
    try:
        print(f"Connection established with {addr}")

        data = conn.recv(BUFFER_SIZE).decode("utf-8").strip()
        print(f"Chunk: {data}")

        if not data:
            response = "ERROR: No data receivedEOF"
            conn.sendall(response.encode("utf-8"))
            return

        parts = data.split()
        if len(parts) != 4:
            response = "ERROR: Invalid payload formatEOF"
            conn.sendall(response.encode("utf-8"))
            return

        endpoint, username, password, identifier = parts
        hashed_identifier = generate_hash(identifier)
        if not hashed_identifier:
            response = "ERROR: Server configuration issueEOF"
            conn.sendall(response.encode("utf-8"))
            return

        if endpoint.upper() == "LOGIN":
            response = handle_login(username, password, hashed_identifier) + "EOF"
        elif endpoint.upper() == "REGISTER":
            response = handle_register(username, password, hashed_identifier) + "EOF"
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
import sys
import subprocess
import sqlite3
import ssl

from tls_transport import (
    HANDSHAKE_TIMEOUT,
    create_server_context,
    wrap_server_connection,
)

from auth import authenticate_user
from database import initialise_database

def install_requirements():
    """Install required libraries before running the script."""
    required_libraries = ['socket', 'os', 'time', 'threading','signal','mimetypes']
    
    # Check if libraries are available, install if not
    for library in required_libraries:
        try:
            __import__(library)
        except ImportError:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', library])
    
    print("All required libraries are installed.")

# Install requirements before importing
install_requirements()

import socket
import os
import time
import signal 
import threading
import mimetypes


HOST = "127.0.0.1"  # loopback

PORT = 9999         # port 9998, works on Saahil's Mac


BUFFER_SIZE = 128 * 1024  # Buffer size (128 KB)

terminate_server = False


uname = dict()
clients = []
termination_clients = []
fc = dict()
# Initialize server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.settimeout(0.5)  # Set a short timeout for non-blocking accept calls

termination_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
termination_socket.settimeout(0.5)

# Signal handler function to gracefully shutdown the server
def signal_handler(signum, frame):
    global terminate_server
    print("\nTermination signal received. Shutting down the server gracefully.")
    terminate_server = True
    for c in tuple(termination_clients):
        try:
            c.sendall(b"Terminate")  # This notification is also TLS-encrypted.
        except OSError:
            pass  # A disconnected client must not prevent server shutdown.
        finally:
            c.close()
    # Closing a socket alone may leave another thread blocked inside recv().
    # shutdown wakes those reads so worker threads can finish before process exit.
    for connection in tuple(clients):
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        finally:
            connection.close()
    server_socket.close()
    termination_socket.close()
    sys.exit(0)

# Register signal handler for SIGINT and SIGTERM
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def validate_user(client, addr):
    """Authenticate before allowing any file operation on this connection."""
    # Retry with a loop instead of recursion, which would grow the call stack
    # after each failed password. The existing wire format remains unchanged.
    while not terminate_server:
        try:
            data = client.recv(BUFFER_SIZE)
            if not data:  # Empty bytes mean the peer closed its connection.
                return False
            try:
                # Split once: the password may itself contain "---".
                username, password = data.decode("utf-8").split("---", 1)
            except (UnicodeDecodeError, ValueError):
                client.sendall(b"Error")
                continue

            # auth.py fetches one SQLite record and verifies its salted hash.
            # No plaintext-file fallback is allowed if SQLite is unavailable.
            if authenticate_user(username, password):
                uname[addr] = username
                fc[username] = 0
                client.sendall(b"200 Success")
                return True

            # The same response covers unknown users and incorrect passwords.
            client.sendall(b"Error")
        except (OSError, ValueError, sqlite3.Error):
            # Fail closed: a disconnected client or database error must never
            # grant access to the file menu. Do not log submitted credentials.
            return False
    return False


def delete_file(client, addr):
    user = uname[addr]
    dir_name = f"server_uploads/client_{user}"
    
    try:
        files = os.listdir(dir_name)
        response = " ".join(files) + " EOF"
        if response == " EOF":
            client.sendall(response.encode())
            return
        client.sendall(response.encode())
        
        file_name = client.recv(BUFFER_SIZE).decode()
        file_path = os.path.join(dir_name, file_name)
        
        if os.path.exists(file_path):
            os.remove(file_path)
            client.sendall(f"File '{file_name}' deleted successfully.\n".encode())
        else:
            client.sendall(f"File '{file_name}' does not exist.\n".encode())
            

        time.sleep(0.5)
        
    except Exception as e:
        client.sendall(f"Error deleting file: {str(e)}\n".encode())
        time.sleep(0.5)



def view_file(client, addr):
    user = uname[addr]
    dir_name = f"server_uploads/client_{user}"
    
    try:
        # Send list of available files
        files = os.listdir(dir_name)
        response = " ".join(files) + " EOF"
        client.sendall(response.encode())
        
        # Receive file name to  view
        file_name = client.recv(BUFFER_SIZE).decode()
        if file_name == "Empty Folder, no files":
            send_options(client,addr)
            return
        file_path = os.path.join(dir_name, file_name)
        
        if not os.path.exists(file_path):
            client.sendall("404 File not found".encode())
            return
        
        mime_type, _ = mimetypes.guess_type(file_path)
        if mime_type and mime_type.split('/')[0] in ['image', 'video']:
            client.sendall("403 Preview not allowed for images or videos".encode())
            return
            
        # Read first 1024 bytes
        with open(file_path, 'rb') as f:
            preview = f.read(1024)
            
        # Send file type and preview
        file_type = "binary" if "\x00" in preview.decode(errors='ignore') else "text"
        client.sendall(f"200 {file_type}".encode())
        time.sleep(0.5)  # Small delay to ensure messages don't merge
        
        if file_type == "text":
            preview_str = preview.decode(errors='ignore')
            client.sendall(preview_str.encode())
        else:
            # For binary files, send hexdump
            import binascii
            hex_preview = binascii.hexlify(preview).decode()
            client.sendall(hex_preview.encode())
            
    except Exception as e:
        client.sendall(f"Error viewing file: {str(e)}".encode())



def send_options(client,addr):
    if terminate_server:
        return
    message = "Enter 1 for uploading a file, 2 for a list of uploaded files, 3 to download a file, 4 to delete a file, 5 to view contents of file, 6 to logout"
    try:
        client.sendall(message.encode())
        response = client.recv(BUFFER_SIZE).decode()
        if(response == '1'):
            fc[uname[addr]] = 0
            write_file(client,addr)
            send_options(client,addr)
        elif(response == '2'):
            fc[uname[addr]] = 0
            message = display_all_files(client,addr)
            response = ""
            if message == "No files in server":
                response = message + " EOF"
            else:
                for name in message:
                    response =response + " " + name
                response =response + " EOF "
            client.sendall(response.encode())
            time.sleep(0.5)
            send_options(client,addr)
        elif response == '3':
            fc[uname[addr]] = 0
            user = uname[addr]
            dir_name = f"server_uploads/client_{user}"
            message = client.recv(BUFFER_SIZE).decode()
            if message == "Send files in drive":
                list_files = os.listdir(dir_name)
                files = ""
                for file in list_files:
                    files += file + " "

                files += "EOF"
                if files == "EOF":
                    # print(files)
                    client.sendall(files.encode())
                    time.sleep(0.5)
                    send_options(client,addr)
                client.sendall(files.encode())
            
            file_name = client.recv(BUFFER_SIZE).decode()
            download_file(client, file_name,addr)
            send_options(client,addr)
        elif response == '4':  # Handle file deletion
            fc[uname[addr]] = 0
            delete_file(client, addr)
            # message = client.recv(BUFFER_SIZE).decode()


            # client.sendall(message.encode())

            time.sleep(0.5)
            send_options(client,addr)

        if response == '5':
            fc[uname[addr]] = 0
            view_file(client, addr)
            time.sleep(0.5)
            send_options(client, addr)
        

        elif response == '6':
            for socket in termination_clients:
                t_ip,t_p = socket.getpeername()
                if t_ip == addr[0] and t_p == addr[1]+1:
                    socket.close()
                termination_clients.remove(socket)
            client.close()
            # sys.exit(1)
        
        # else:
        #     # time.sleep(0.25)
        #     if fc[uname[addr]] > 5:
        #         try:
        #             client.sendall("Due to too many failed requests, server has decided to terminate".encode())
        #             client.close()
        #             for socket in termination_clients:
        #                 t_ip,t_p = socket.getpeername()
        #                 if t_ip == addr[0] and t_p == addr[1]+1:
        #                     socket.close()
        #                 termination_clients.remove(socket)
        #         except:
        #             pass
        #         return
        #     fc[uname[addr]]+=1
        #     send_options(client,addr)
    except:
        pass


def write_file(client,addr):
    if terminate_server:
        return
    user = uname[addr]
    dir_name = f"server_uploads/client_{user}"
    os.makedirs(dir_name, exist_ok=True)

    # Receive the file name from the client
    file_name = client.recv(BUFFER_SIZE).decode()
    file_path = os.path.join(dir_name, file_name)

    with open(file_path, "wb") as f:
        # prev = ""
        while True:
            # if prev.endswith(b"EOF"):
            #     break
            # data_chunk = client.recv(BUFFER_SIZE)
            # f.write(data_chunk)
            # prev = data_chunk
            data_chunk = client.recv(BUFFER_SIZE)
            if data_chunk.endswith(b"EOF"):
                f.write(data_chunk[:-len("EOF")])
                break
            f.write(data_chunk)
    print(f"File received and saved as {file_path}")
    # send_options(client,addr)
    return 


def download_file(client, file_name,addr):
    if terminate_server:
        return
    user = uname[addr]
    dir_name = f"server_uploads/client_{user}"
    file_path = os.path.join(dir_name, file_name)
    # dir_name = f"client_{user}"
    
    if file_name not in os.listdir(dir_name):
        response = "404"
        client.sendall(response.encode())
        new_filename = client.recv(BUFFER_SIZE).decode()
        download_file(client,new_filename,addr)
    else:
        try:
            response = "200"
            client.sendall(response.encode())
            with open(file_path, "rb") as f:
                while (chunk := f.read(BUFFER_SIZE)):
                    client.sendall(chunk)
                client.sendall("EOF".encode())
            print(f"File '{file_name}' sent successfully.")
            time.sleep(0.5)
            message = client.recv(BUFFER_SIZE).decode()
            if message == "Rx Complete":
                # send_options(client,addr)
                return
            
        except Exception as e:
            print(f"Error occurred while sending file '{file_name}': {e}")
            time.sleep(0.5)
            send_options(client,addr)



def display_all_files(client,addr):
    if terminate_server:
        return
    user = uname[addr]
    dir_name = f"./server_uploads/client_{user}"

    os.makedirs(dir_name, exist_ok=True)

    if len(os.listdir(dir_name)) > 0:
        return os.listdir(dir_name)
    else:
        return "No files in server"

def on_user(client,addr,t_c):
    if terminate_server:
        return
    clients.append(client)
    termination_clients.append(t_c)
    
    # A failed login must end this handler, not fall through into the file menu.
    if not validate_user(client, addr):
        client.close()
        t_c.close()
        if client in clients:
            clients.remove(client)
        if t_c in termination_clients:
            termination_clients.remove(t_c)
        return


    if terminate_server:
        return
    send_options(client,addr)

    return

def establish_communication(host, port):
    if terminate_server:
        return

    # Fail before listening if the certificate/key is missing or invalid. The
    # same server identity protects both the data port and notification port.
    context = create_server_context()
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    termination_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    termination_socket.bind((host, port + 1))
    server_socket.listen(5)
    termination_socket.listen(5)
    print(f"TLS server listening on {host}:{port} and {host}:{port + 1}")

    while not terminate_server:
        client = t_c = None
        try:
            client, address = server_socket.accept()
        except socket.timeout:
            continue  # Recheck the shutdown flag periodically.

        try:
            # Complete this handshake BEFORE waiting for the second connection.
            # The client verifies it before connecting its notification socket;
            # reversing this order would deadlock the client and server.
            client = wrap_server_connection(client, context)

            # Do not let an incomplete connection pair block all later clients
            # forever. The helper also bounds each individual TLS handshake.
            termination_socket.settimeout(HANDSHAKE_TIMEOUT)
            t_c, _ = termination_socket.accept()
            t_c = wrap_server_connection(t_c, context)

            print(f"TLS transport established: {client.version()}")
            thread = threading.Thread(target=on_user, args=(client, address, t_c))
            thread.start()
        except (OSError, ssl.SSLError):
            # Reject plaintext, stalled handshakes, and disconnected peers. Never
            # fall back to raw TCP or pass a half-secured pair into on_user().
            for connection in (client, t_c):
                if connection is not None:
                    connection.close()
            print("Connection rejected: TLS handshake or connection pair failed.")


if __name__ == "__main__":
    # Schema creation is idempotent: existing users are preserved. An empty
    # database grants no access until an account is created through auth.py.
    try:
        initialise_database()
    except (OSError, ValueError, sqlite3.Error):
        sys.exit("Cannot initialise account database; server was not started.")
    try:
        establish_communication(HOST, PORT)
    except (OSError, ssl.SSLError) as error:
        sys.exit(f"Server startup failed: {error}. For certificates, run python3 setup_tls.py.")
    finally:
        server_socket.close()
        termination_socket.close()

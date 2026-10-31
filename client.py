import subprocess
import sys
import getpass

def install_requirements():
    """Install required libraries before running the script."""
    required_libraries = ['socket', 'os', 'time', 'threading','signal']
    
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
import threading
import signal


HOST = "127.0.0.1"  # Server IP (localhost)
PORT = 9999         # Server port (matching the server)
BUFFER_SIZE = 128 * 1024  # Buffer size (128 KB)

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

termination_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
termination_socket.connect((HOST, PORT + 1))

terminate = False
login = False

def signal_handler(signum, frame):
    global terminate_server
    print("\nTermination signal received. Shutting down the client gracefully.")
    client_socket.close()
    os._exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def on_terminate():
    global terminate
    while True:
        try:
            message = termination_socket.recv(BUFFER_SIZE).decode()
            if message == "Terminate":
                terminate = True
                print("\nServer has been terminated. Closing connection...")
                try:
                    client_socket.close()
                    termination_socket.close()
                except:
                    pass
                os._exit(1)  # Force terminate all threads
        except (socket.error, ConnectionAbortedError):
            # If server suddenly closes 
            terminate = True
            print("\nClosing client...")
            try:
                client_socket.close()
                termination_socket.close()
            except:
                pass
            os._exit(1)  # Force terminate all threads
        except Exception as e:
            # Handle any other unexpected errors
            terminate = True
            print(f"\nUnexpected error: {str(e)}. Closing client...")
            try:
                client_socket.close()
                termination_socket.close()
            except:
                pass
            os._exit(1)  # Force terminate all threads

def clean_shutdown():
    global terminate
    terminate = True
    print("Connection closed, Thank You for using")
    try:
        client_socket.close()
        termination_socket.close()
    except:
        pass
    os._exit(0)

def send_file(file_path):
    if terminate:
        return
    file_name = os.path.basename(file_path)
    client_socket.sendall(file_name.encode())
    time.sleep(0.2)
    try:
        with open(file_path, "rb") as f:
            while not terminate and (chunk := f.read(BUFFER_SIZE)):
                client_socket.sendall(chunk)
            client_socket.sendall(".EOF".encode())
        print(f"File '{file_name}' sent successfully.")
    except Exception as e:
        print(f"File '{file_name}' could not be uploaded. Error: {e}")

def view_file_preview():
    if terminate:
        return
        
    # Receive list of available files
    files = client_socket.recv(BUFFER_SIZE).decode()
    files = [file for file in files.split(" ") if file != "EOF"]
    files = " ".join(file for file in files)
    if files.strip() == "":
        print("No available files")
        client_socket.sendall("Empty Folder, no files".encode())
        return
    print("\nAvailable files:", files)
    
    # Send file name to view
    file_name = input("Enter the name of the file to preview: ")
    client_socket.sendall(file_name.encode())
    
    # Receive response
    status = client_socket.recv(BUFFER_SIZE).decode()
    if status.startswith("404"):
        print("File not found")
        return
        
    if status.startswith("200"):
        file_type = status.split()[1]
        preview = client_socket.recv(BUFFER_SIZE).decode()
        preview = " ".join(word for word in preview.split(".") if "EOF" not in word)
        print("\n=== File Preview ===")
        if file_type == "text":
            print(preview)
        else:
            print("Binary file preview (hexadecimal):")
            # Format hex dump in readable chunks
            for i in range(0, len(preview), 32):
                chunk = preview[i:i+32]
                hex_line = ' '.join(chunk[j:j+2] for j in range(0, len(chunk), 2))
                print(f"{i:04x}: {hex_line}")
        print("=== End Preview ===\n")
    else:
        print("Error viewing file:", status)

def receive_file(file_name):
    if terminate:
        return
    dir_name = f'./fromserver/{username}'
    os.makedirs(dir_name, exist_ok=True)

    file_path = os.path.join(dir_name, file_name)
    ans = ""
    response = client_socket.recv(BUFFER_SIZE).decode()
    if response == "404":
        print(f"'{file_name}' does not exist")
        new_filename = input("Please enter a file name from the list displayed above:\t").encode()
        client_socket.sendall(new_filename)
        receive_file(new_filename.decode())
    else:
        with open(file_path, "wb") as f:
            print(f"Receiving file '{file_name}'...")
            while not terminate:
                data_chunk = client_socket.recv(BUFFER_SIZE)
                if b"EOF" in data_chunk:
                    f.write(data_chunk.replace(b"EOF", b""))
                    break
                f.write(data_chunk)
        client_socket.sendall("Rx Complete".encode())
        print(f"File received and saved as '{file_path}'")

def main():
    global terminate
    flag = True
    while flag and not terminate:
        global username
        global password
        if terminate:
            os._exit(1)  # Force terminate all threads
        username = input("Username:\t\t")
        if terminate:
            os._exit(1)  # Force terminate all threads
        password = getpass.getpass("Password:\t\t")

        if terminate:
            os._exit(1)  # Force terminate all threads
        identity = username + "---" + password
        if terminate:
            os._exit(1)  # Force terminate all threads
        client_socket.sendall(identity.encode())

        if terminate:
            os._exit(1)  # Force terminate all threads
        auth_status = client_socket.recv(BUFFER_SIZE).decode()

        if auth_status == "200 Success":
            global login
            login = True
            while login and not terminate:
                options = client_socket.recv(BUFFER_SIZE).decode()
                if options == "Due to too many failed requests, server has decided to terminate":
                    print(options)
                    os._exit(1)
                if options == "":
                    os._exit(1)  # Force terminate all threads
                
                ctr = 0
                while True:
                    if ctr > 5:
                        print("Too many invalid inputs, closing client")
                        os._exit(1)
                    use_case = input(options + ":\t\t")
                    
                    # Added check for empty input or non-integer input
                    try:
                        use_case_int = int(use_case.strip())
                        if 0 < use_case_int < 7:
                            break
                        else:
                            print("Please enter a valid option")
                            ctr += 1
                    except (ValueError, TypeError):
                        print("Please enter a valid option")
                        ctr += 1

                if terminate:
                    os._exit(1)
                
                client_socket.sendall(use_case.encode())
                if use_case == '1' and not terminate:
                    file_found = False
                    while not file_found and not terminate:
                        file_path = input("Enter the filepath (absolute) to be uploaded: ")
                        if os.path.isfile(file_path):
                            send_file(file_path)
                            flag = False
                            file_found = True
                        else:
                            print("File not found. Please check the path and try again.")
                        
                elif use_case == '2' and not terminate:
                    files = b""
                    while not terminate:
                        chunk = client_socket.recv(BUFFER_SIZE)
                        if b"EOF" in chunk:
                            files += chunk.replace(b"EOF", b"")
                            break
                        files += chunk
                    # print(files.decode())
                    if files.decode().strip() == "No files in server":
                        print("No files on server")
                    elif files.decode().strip() != "":
                        print([file for file in files.decode().split()])
                    flag = False
                
                elif use_case == '6' and not terminate:
                    # client_socket.close()
                    # termination_socket.close()
                    # print("Connection closed, Thank You for using")
                    # flag = False
                    # login = False
                    # os.exit(1)
                    clean_shutdown()

                elif use_case == '4':  # New delete file option
                    # Receive and display list of files
                    files = client_socket.recv(BUFFER_SIZE).decode().strip()
                    files = files.replace(" EOF", "")
                    if files == "EOF":
                        print("No files to delete")
                        continue
                    print("Available files:", files)
                    
                    # Send file name to delete
                    file_name = input("Enter the name of the file to delete: ")
                    client_socket.sendall(file_name.encode())
                    
                    # Receive and display deletion status
                    response = client_socket.recv(BUFFER_SIZE).decode()
                    print(response)

                elif use_case == '5' and not terminate:
                    view_file_preview()
                

                elif use_case == '3' and not terminate:
                    time.sleep(0.25)
                    client_socket.sendall("Send files in drive".encode())
                    message = b""
                    while not terminate:
                        response = client_socket.recv(BUFFER_SIZE)
                        if "EOF".encode() in response:
                            message += response
                            break
                        message += response
                    message = message.decode()
                    files = " ".join([file for file in message.split() if "EOF" not in file])
                    if message.strip() == "EOF":
                        print("No files uploaded.")
                        continue
                    print(f"Files in drive: {files}")
                    file_name = input("Enter the file name to download: ")
                    client_socket.send(file_name.encode())
                    receive_file(file_name)
                    flag = False
                else:
                    print("Invalid option")
        elif not terminate:
            print("Invalid Password")

if __name__ == "__main__":
    t1 = threading.Thread(target=main)
    t2 = threading.Thread(target=on_terminate)
    t2.start()
    t1.start()

    t1.join()
    t2.join()

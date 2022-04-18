import os
import socket

IP = None
PORT = None
ADDR = None
BUFFER_SIZE = 4096
FORMAT = "utf-8"
DEBUG = None
server = None
connected = False

# Response codes
rescode_put_change_success = 0
rescode_get_success = 1
rescode_file_not_found = 2
rescode_unknown_req = 3
rescode_change_fail = 5
rescode_help = 6


def to_print(string):
    if DEBUG == 1:
        print(string)


def first_byte(rescode, file_name):  # Add rescode to response message
    first = rescode << 5
    first |= len(file_name)
    return first


def opcode_extract(first):  # Extract the request code
    opcode = first >> 5
    return opcode


def init():  # Open socket
    global IP
    global PORT
    global DEBUG
    global ADDR
    global DEBUG

    print("Enter the following: IP Port Debug_Mode(0 off/ 1 on)")
    user_input = input("Input: ")
    user_config = user_input.split(" ")
    IP = user_config[0]
    PORT = int(user_config[1])
    DEBUG = int(user_config[2])
    ADDR = (IP, PORT)

    # IP = "127.0.0.1"
    # PORT = 4444
    # DEBUG = 1
    # ADDR = (IP, PORT)

    print("[STARTING] Starting Server...")

    # Start TCP Socket
    global server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind IP and PORT to Server
    server.bind(ADDR)


def run():  # Run Server
    global connected

    while not connected:
        # Server is listening
        server.listen()
        print("[LISTENING] Server is listening...")

        # Accept Client connection
        conn, addr = server.accept()
        print(f"[CONNECTION] {addr} connected")
        connected = True

        while connected:
            # Receive header from Client
            header = bytearray(conn.recv(BUFFER_SIZE))
            to_print(f"[RECV] Received request")
            opcode = opcode_extract(header[0])

            if opcode == 0:
                server_put(header, conn)
            elif opcode == 1:
                server_get(header, conn)
            elif opcode == 2:
                server_change(header, conn)
            elif opcode == 3:
                server_help(conn)
            elif opcode == 4:
                server_bye()
            else:
                server_unknown(conn)


def server_put(header, conn):
    # Copy file to server_data
    # Extract information
    file_name = ""
    file_name_size = header[0] & 0x1F
    for x in range(1, 1 + file_name_size):
        file_name += chr(header[x])
    file_size = int.from_bytes(header[1 + file_name_size: 1 + file_name_size + 4], byteorder='big')
    to_print("[RECV] PUT " + file_name)

    # Receive file
    current_size = 0
    buffer = b""
    with open("server_data/" + file_name, "wb") as f:
        while current_size < file_size:
            bytes_read = conn.recv(BUFFER_SIZE)
            if not bytes_read:
                break
            if len(bytes_read) + current_size > file_size:
                bytes_read = bytes_read[:file_size-current_size]
            buffer += bytes_read
            f.write(buffer)
            current_size += len(bytes_read)
    f.close()

    # Make response message
    response = bytes()
    response += first_byte(rescode_put_change_success, "").to_bytes(1, 'big')  # Sets rescode and file name size
    conn.send(response)
    to_print("[SEND] Response " + format(rescode_put_change_success, 'b').zfill(3))


def server_get(header, conn):
    # Extract information
    file_name = ""
    file_name_size = header[0] & 0x1F
    for x in range(1, 1 + file_name_size):
        file_name += chr(header[x])
    to_print("[RECV] GET " + file_name)

    try:
        # Get file size
        file_size = os.path.getsize("server_data/" + file_name)

        # Make response message
        response = bytes()
        response += first_byte(rescode_get_success, file_name).to_bytes(1, 'big')  # Sets rescode and file name size
        response += file_name.encode(FORMAT)
        response += file_size.to_bytes(4, 'big')
        conn.send(response)
        to_print("[SEND] Response " + format(rescode_get_success, 'b').zfill(3))

        # Send file
        with open("server_data/" + file_name, "rb") as f:
            while True:
                bytes_read = f.read(BUFFER_SIZE)
                if not bytes_read:
                    break
                conn.sendall(bytes_read)
        f.close()
        to_print("[SEND] GET " + file_name)

    except IOError:  # Unable to locate file
        # Make response message
        response = bytes()
        response += first_byte(rescode_file_not_found, "").to_bytes(1, 'big')  # Sets rescode and file name size
        conn.send(response)
        to_print("[SEND] Response " + format(rescode_file_not_found, 'b').zfill(3))
        to_print("[ERROR] file does not exist")


def server_change(header, conn):
    # Extract information
    file_name = ""
    file_name_size = header[0] & 0x1F
    for x in range(1, 1 + file_name_size):
        file_name += chr(header[x])

    new_file_name = ""
    new_file_name_size = header[1 + file_name_size]
    for x in range(2 + file_name_size, 2 + file_name_size + new_file_name_size):
        new_file_name += chr(header[x])

    to_print("[RECV] CHANGE " + file_name + " " + new_file_name)

    try:
        # Rename file
        os.rename("server_data/" + file_name, "server_data/" + new_file_name)

        # Make response message
        response = bytes()
        response += first_byte(rescode_put_change_success, "").to_bytes(1, 'big')  # Sets rescode and file name size
        conn.send(response)
        to_print("[SEND] Response " + format(rescode_put_change_success, 'b').zfill(3))

    except IOError:  # Unable to locate file
        # Make response message
        response = bytes()
        response += first_byte(rescode_change_fail, "").to_bytes(1, 'big')  # Sets rescode and file name size
        conn.send(response)
        to_print("[SEND] Response " + format(rescode_change_fail, 'b').zfill(3))
        to_print("[ERROR] fail file name change")


def server_help(conn):
    # Help message
    help_message = "put\nget\nchange\nhelp\nbye"
    # Make response message
    response = bytes()
    response += first_byte(rescode_help, help_message).to_bytes(1, 'big')  # Sets rescode and file name size
    response += help_message.encode(FORMAT)

    conn.send(response)
    to_print("[SEND] Response " + format(rescode_help, 'b').zfill(3))


def server_bye():
    global connected
    connected = False
    to_print("[BYE] Client")


def server_unknown(conn):
    # Make response message
    response = bytes()
    response += first_byte(rescode_unknown_req, "").to_bytes(1, 'big')  # Sets rescode and file name size
    conn.send(response)
    to_print("[SEND] Response " + format(rescode_unknown_req, 'b').zfill(3))
    to_print("[ERROR] Unknown request")


def main():
    init()
    run()


if __name__ == "__main__":
    main()

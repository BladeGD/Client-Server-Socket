"""
Teng Zhao
Student ID: 40089560
Client program file
I certify that I am the sole author of this file
"""

import os.path
import socket

IP = None
PORT = None
ADDR = None
BUFFER_SIZE = 4096
FORMAT = "utf-8"
DEBUG = None
client = None

# Request codes
opcode_put = 0
opcode_get = 1
opcode_change = 2
opcode_help = 3
opcode_bye = 4
opcode_unknown = 5


def to_print(string):
    if DEBUG == 1:
        print(string)


def first_byte(opcode, file_name):  # Add opcode and file name size to request message
    first = opcode << 5
    first |= len(file_name)
    return first


def rescode_extract(first):  # Extract the response code
    rescode = first >> 5
    return rescode


def init():  # Connect socket
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

    # Start TCP Socket
    global client
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to Server
    client.connect(ADDR)


def run():  # Run Client
    while True:
        user_input = input(f"Enter command: ")
        user_command = user_input.split(" ")
        user_command[0] = user_command[0].lower()

        if user_command[0] == "put":
            put_function(user_command[1])
        elif user_command[0] == "get":
            get_function(user_command[1])
        elif user_command[0] == "change":
            change_function(user_command[1], user_command[2])
        elif user_command[0] == "help":
            help_function()
        elif user_command[0] == "bye":
            bye_function()
        else:
            unknown_function()


def put_function(file_name):
    try:
        # Get file size
        file_size = os.path.getsize("client_data/" + file_name)

        # Make request message
        header = bytes()
        header += first_byte(opcode_put, file_name).to_bytes(1, 'big')  # Sets opcode and file name size
        header += file_name.encode(FORMAT)
        header += file_size.to_bytes(4, 'big')

        # Send request message
        client.send(header)

        # Send file
        with open("client_data/" + file_name, "rb") as f:
            while True:
                bytes_read = f.read(BUFFER_SIZE)
                if not bytes_read:
                    break
                client.sendall(bytes_read)
        f.close()
        to_print("[SEND] PUT " + file_name)

        # Receive Server response
        message = client.recv(BUFFER_SIZE)
        rescode = rescode_extract(message[0])
        if rescode == 0:
            to_print("[SERVER] " + format(rescode, 'b').zfill(3) + " PUT " + file_name + " success")
    except IOError:  # Unable to locate file
        print("[ERROR] file does not exist")


def get_function(file_name):
    # Make request message
    header = bytes()
    header += first_byte(opcode_get, file_name).to_bytes(1, 'big')  # Sets opcode and file name size
    header += file_name.encode(FORMAT)

    # Send request message
    client.send(header)
    to_print("[SEND] GET " + file_name)

    # Obtain response
    message = bytearray(client.recv(BUFFER_SIZE))

    # Process Response
    rescode = rescode_extract(message[0])
    to_print("[RECV] Received response ")
    if rescode == 1:
        # Copy found file to client_data
        # Extract information
        file_name = ""
        file_name_size = message[0] & 0x1F
        for x in range(1, 1 + file_name_size):
            file_name += chr(message[x])
        file_size = int.from_bytes(message[1 + file_name_size: 1 + file_name_size + 4], byteorder='big')

        # Receive file
        current_size = 0
        buffer = b""
        with open("client_data/" + file_name, "wb") as f:
            while current_size < file_size:
                bytes_read = client.recv(BUFFER_SIZE)
                if not bytes_read:
                    break
                if len(bytes_read) + current_size > file_size:
                    bytes_read = bytes_read[:file_size - current_size]
                buffer += bytes_read
                f.write(buffer)
                current_size += len(bytes_read)
        f.close()
        to_print("[SERVER] " + format(rescode, 'b').zfill(3) + " GET " + file_name + " success")
    elif rescode == 2:
        # File not found on server
        print("[SERVER] " + format(rescode, 'b').zfill(3) + " file not found")
    else:
        pass


def change_function(file_name, new_file_name):
    # Make request message
    header = bytes()
    header += first_byte(opcode_change, file_name).to_bytes(1, 'big')  # Sets opcode and file name size
    header += file_name.encode(FORMAT)
    header += len(new_file_name).to_bytes(1, 'big')
    header += new_file_name.encode(FORMAT)

    # Send request message
    client.send(header)
    to_print("[SEND] CHANGE " + file_name + " " + new_file_name)

    # Receive Server response
    message = client.recv(BUFFER_SIZE)
    rescode = rescode_extract(message[0])
    to_print("[RECV] Received response ")
    if rescode == 0:
        to_print("[SERVER] " + format(rescode, 'b').zfill(3) + " CHANGE success")
    elif rescode == 5:
        print("[SERVER] " + format(rescode, 'b').zfill(3) + " CHANGE fail")
    else:
        pass


def help_function():
    # Make request message
    header = bytes()
    header += first_byte(opcode_help, "").to_bytes(1, 'big')  # Sets opcode and file name size

    # Send request message
    client.send(header)
    to_print("[SEND] HELP")

    # Receive Server response
    message = client.recv(BUFFER_SIZE)
    rescode = rescode_extract(message[0])
    to_print("[RECV] Received response ")
    if rescode == 6:
        message_content = ""
        message_size = message[0] & 0x1F
        for x in range(1, 1 + message_size):
            message_content += chr(message[x])
        print(message_content)
        to_print("[SERVER] " + format(rescode, 'b').zfill(3) + " HELP received")
    else:
        print("[SERVER] " + format(rescode, 'b').zfill(3) + " HELP fail")


def bye_function():
    # Make request message
    header = bytes()
    header += first_byte(opcode_bye, "").to_bytes(1, 'big')  # Sets opcode and file name size

    # Send request message
    client.send(header)
    to_print("[SEND] BYE ")
    client.close()
    print("[BYE]")
    exit()


def unknown_function():
    # Make request message
    header = bytes()
    header += first_byte(opcode_unknown, "").to_bytes(1, 'big')  # Sets opcode and file name size
    client.send(header)

    # Receive Server response
    message = client.recv(BUFFER_SIZE)
    rescode = rescode_extract(message[0])
    print("[SERVER] " + format(rescode, 'b').zfill(3) + " Unknown command")


def main():
    init()
    run()


if __name__ == "__main__":
    main()

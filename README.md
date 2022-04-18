# Client-Server-Socket
Simple file transfer service developed via  python stream sockets to partially simulate the file transfer protocol (FTP).
Files are included in the test_data folder to use for commands.

1. Run the server.py program and input desired IP, PORT, and DEBUG code (1 for ON/ 0 for OFF)
2. Rune the client.py program and input desired IP, PORT, and DEBUG code (1 for ON/ 0 for OFF)
3. Type in commands into the client program, support commands are the following:
	* put fileName - uploads file from the client_data folder to the server_date folder
	* get fileName - downloads file from the server_data folder to the client_data folder
	* change oldFileName newFileName - change file with oldFileName on the server to newFile Name
	* help - gets list of valid commands from the server
	* bye - closes connection with the server
4. Server will keep listening for new connection once connected client is closed

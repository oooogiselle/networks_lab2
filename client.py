import socket
import sys

'''
    Command-line HTTP/1.1 GET client using raw sockets

    Author: Giselle Wu, Dartmouth CS60, Fall 2026
            Starter template by Tim Pierson, assisted by Microsoft Copilot
            Assisted by Claude (Anthropic): fixed the receive loop, raw-byte output and argument handling

    run: python3 client.py <server_host> <server_port> <path>
    e.g. python3 client.py localhost 8080 helloworld.html

    Prints the raw response (status line, headers, and body) to the terminal.
'''

if len(sys.argv) != 4:
    print("Usage: python3 client.py <server_host> <server_port> <path>")
    sys.exit(1)

#server's ip and port, plus the file to request
HOST = sys.argv[1]
PORT = int(sys.argv[2])
PATH = sys.argv[3].lstrip("/") #accept "helloworld.html" or "/helloworld.html"

#create TCP socket to connect to server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

try:
    message = f"GET /{PATH} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nConnection: close\r\n\r\n"
    client_socket.sendall(message.encode()) #encode converts to bytes

    #read server's response. one recv() won't return a big file, so keep reading
    #until the server closes the connection (we asked for that with Connection: close)
    response = b""
    while True:
        data = client_socket.recv(4096)
        if not data: #empty bytes means the server finished and closed
            break
        response += data
finally:
    client_socket.close()

#write the raw bytes so files that aren't valid utf-8 can't crash a decode
sys.stdout.buffer.write(response)
sys.stdout.buffer.flush()

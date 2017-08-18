from argparse import ArgumentParser
from stem.control import Controller
import socket, socks
import threading
from Crypto.PublicKey import RSA
from Crypto import Random

# Change these for your application.
host = '127.0.0.1'  # localhost
control_port = 9151  # server port
hidden_svc_port = 38906  # client's hidden service port
password = ''  # password for the tChat server
key_size = 2048  # RSA key size (use 4096 if you're paranoid)


class Client:
    def __init__(self, conn, pub_key):
        """
        Basic client object that contains information for each connected client.
        
        :param conn: A client's connection
        :param pub_key: A client's public key
        """
        self.conn = conn
        self.pub_key = pub_key


def start_hidden_service():
    """
    Starts the (server-side) hidden service.
    
    :return: the hidden service address to connect to
    """
    controller = Controller.from_port(address=host, port=control_port)  # Create a hidden service controller

    hidden_svc_dir = 'C:/tmp/'  # base directory for the hidden service
    try:
        controller.authenticate(password=password)  # set the password for the service
        controller.set_options([
            ('HiddenServiceDir', hidden_svc_dir),
            ('HiddenServicePort', '%d %s:%d' % (hidden_svc_port, host, hidden_svc_port)),
        ])
        svc_name = open('%s/hostname' % hidden_svc_dir, 'r').read().strip()
        return svc_name
    except Exception as e:
        print e  # print out any exceptions that may occur


def listen_for_client_messages(client, client_list):
    """
    Listens for client messages to send to all connected clients (server-side)
    
    :param client: user's Client object
    :param client_list: server's list of all Client objects
    :return: None
    """
    try:
        # Listen for client messages
        while True:
            msg = client.conn.recv(key_size)  # Accept an incoming message
            for other_client in client_list:  # For each other connected client:
                enc_msg = other_client.pub_key.encrypt(msg)  # Encrypt the message
                other_client.conn.sendall(enc_msg)  # Send the message
    finally:
        client.conn.close()  # Close the connection on exit


def start_server():
    """
    Starts the tChat server (server-side).
    
    :return: None
    """
    private_key = RSA.generate(key_size, Random.new().read)  # Generate a private key for the server
    public_key = private_key.publickey()  # Generate a public key for the server

    svc_name = start_hidden_service()  # Start the hidden service, returns service address
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, hidden_svc_port))  # Bind the server's listening socket
    client_list = []  # list of connected Client objects
    print 'Server Started with URL: %s' % svc_name

    server_socket.listen(5)
    # Main server listening loop
    try:
        while True:
            conn, addr = server_socket.accept()  # Accept a connecting client
            print 'Client connected. '
            # Key exchange with the client
            client_pub_key = RSA.importKey(conn.recv(key_size))
            conn.sendall(public_key.exportKey())
            # Begin a thread to listen for messages from this client
            this_client = Client(conn, client_pub_key)
            client_list.append(this_client)
            t = threading.Thread(target=listen_for_client_messages, args=(this_client, client_list))
            t.start()
    finally:
        server_socket.close()  # Close the listening socket


def listen_for_server_messages(client_socket, private_key):
    """
    Listen for incoming messages from other clients relayed through the server.
    
    :param client_socket: Client's listening socket
    :param private_key: Client's private key
    :return: None
    """
    try:
        # Main client listening loop
        while True:
            enc_msg = client_socket.recv(key_size)  # Receive the message
            msg = private_key.decrypt(enc_msg)  # Decrypt the message
            print msg  # Display the message
    finally:
        client_socket.close()  # Close the socket on exit


def start_client(onion_url):
    """
    Start the tChat client.
    
    :param onion_url: the hidden service's address
    :return: None
    """
    private_key = RSA.generate(key_size, Random.new().read)  # Generate a private key for the client
    public_key = private_key.publickey()  # Generate a public key for the client
    # Open client sockets and connect to the server
    client_sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.setproxy(socks.PROXY_TYPE_SOCKS5, host, control_port)
    print 'Attempting connection...'
    client_sock.connect((onion_url, hidden_svc_port))
    print 'Connected to %s' % onion_url
    # Key exchange with the server
    client_sock.sendall(public_key.exportKey())
    server_public_key = client_sock.recv(key_size)
    # Begin a thread to listen for messages from the server
    t = threading.Thread(target=listen_for_server_messages, args=(client_sock, private_key))
    t.start()
    # Main client loop
    while True:
        try:
            msg = raw_input('> ')  # Input a message
            enc_msg = server_public_key.encrypt(msg)  # Encrypt the message
            client_sock.sendall(enc_msg)  # Send the message to the server
        finally:
            client_sock.close()  # Close the socket on exit


if __name__ == '__main__':
    # Parse the command line arguments and start the program
    parser = ArgumentParser()
    parser.add_argument('-c', type=str, help='Run in client mode')  # e.g. python tChat.py -c aksjhfklashf.onion
    parser.add_argument('-s', action='store_true', help='Run in server mode')  # e.g. python tChat.py -s
    args = parser.parse_args()
    if args.c:
        start_client(args.c)
    elif args.s:
        start_server()

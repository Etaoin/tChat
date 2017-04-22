from argparse import ArgumentParser
from stem.control import Controller
import socket, socks
import threading
from Crypto.PublicKey import RSA
from Crypto import Random

host = '127.0.0.1'
control_port = 9151
hidden_svc_port = 38906
password = ''

key_size = 2048


class Client:
    def __init__(self, conn, pub_key):
        self.conn = conn
        self.pub_key = pub_key


def start_hidden_service():
    controller = Controller.from_port(address=host, port=control_port)

    hidden_svc_dir = 'C:/tmp/'
    try:
        controller.authenticate(password=password)
        controller.set_options([
            ('HiddenServiceDir', hidden_svc_dir),
            ('HiddenServicePort', '%d %s:%d' % (hidden_svc_port, host, hidden_svc_port)),
        ])
        svc_name = open('%s/hostname' % hidden_svc_dir, 'r').read().strip()
        return svc_name
    except Exception as e:
        print e


def listen_for_client_messages(client, client_list):
    try:
        while True:
            msg = client.conn.recv(key_size)
            for other_client in client_list:
                enc_msg = other_client.pub_key.encrypt(msg)
                other_client.conn.sendall(enc_msg)
    finally:
        client.close()


def start_server():
    private_key = RSA.generate(key_size, Random.new().read)
    public_key = private_key.publickey()

    svc_name = start_hidden_service()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, hidden_svc_port))
    client_list = []
    print 'Server Started with URL: %s' % svc_name

    server_socket.listen(5)
    try:
        while True:
            conn, addr = server_socket.accept()
            print 'Client connected. '

            client_pub_key = RSA.importKey(conn.recv(key_size))
            conn.sendall(public_key.exportKey())

            this_client = Client(conn, client_pub_key)
            client_list.append(this_client)
            t = threading.Thread(target=listen_for_client_messages, args=(this_client, client_list))
            t.start()
    finally:
        server_socket.close()


def listen_for_server_messages(client_socket, private_key):
    try:
        while True:
            enc_msg = client_socket.recv(key_size)
            msg = private_key.decrypt(enc_msg)
            print msg
    finally:
        client_socket.close()


def start_client(onion_url):
    private_key = RSA.generate(key_size, Random.new().read)
    public_key = private_key.publickey()

    client_sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.setproxy(socks.PROXY_TYPE_SOCKS5, host, control_port)
    print 'Attempting connection...'
    client_sock.connect((onion_url, hidden_svc_port))
    print 'Connected to %s' % onion_url

    client_sock.sendall(public_key.exportKey())
    server_public_key = client_sock.recv(key_size)

    t = threading.Thread(target=listen_for_server_messages, args=(client_sock, private_key))
    t.start()
    while True:
        try:
            msg = raw_input('> ')
            enc_msg = server_public_key.encrypt(msg)
            client_sock.sendall(enc_msg)
        finally:
            client_sock.close()


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-c', type=str, help='Run in client mode')
    parser.add_argument('-s', action='store_true', help='Run in server mode')
    args = parser.parse_args()

    if args.c:
        start_client(args.c)
    elif args.s:
        start_server()

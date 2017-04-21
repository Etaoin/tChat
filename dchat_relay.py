# Simple relay to get messages to users
import os, socket, thread, pickle
from Crypto.PublicKey import RSA
from Crypto import Random


class Client:
    def __init__(self, conn, pub_key):
        self.conn = conn
        self.pub_key = pub_key


def command_line():
    while True:
        try:
            command_args = raw_input('> ').split()
            if command_args[0] == 'create':
                os.makedirs(command_args[1])
                pickle.dump([], '%s\\whitelist' % command_args[1])
                channels[command_args[1]] = []
                pickle.dump(channels, channels_file)
            elif command_args[1] == 'add':
                if os.path.exists(command_args[0]):
                    whitelist = pickle.load('%s\\whitelist' % command_args[0])
                    pickle.dump(whitelist.append(command_args[2]), '%s\\whitelist' % command_args[1])
        except IndexError:
            print 'Commands:'
            print '\tcreate [channel_name]'
            print '\t[channel_name] add [private_key_hash]'


def on_new_client(conn):
    try:
        conn.sendall(public_key.exportKey())  # Send server's public key
        client_public_key = RSA.importKey(conn.recv(2048))  # Receive client's public key
        # All communications after this line are encrypted
        client_private_hash = private_key.decrypt(conn.recv(2048))  # Receive client's hashed private key
        channel = private_key.decrypt(conn.recv(2048))  # Receive client channel request
        # If channel exists, check hashes in channel for match
        if os.path.exists(channel) and client_private_hash in pickle.load('%s\\whitelist' % channel):
            while True:
                channels[channel].append(Client(conn, client_public_key))
                client_msg = private_key.decrypt(conn.recv(2048))
                for chatter in channels[channel]:
                    chatter.sendall(chatter.pub_key.encrypt(client_msg))
        # If no channel, give option to create new channel
        else:
            conn.sendall(client_public_key.encrypt('NO_CHANNEL'))  # Server command
    finally:
        conn.close()  # Close connection on end


def main():
    if not os.path.exists('Public_Keys'):
        os.makedirs('Public_Keys')

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 9001))

    thread.start_new_thread(command_line, ())

    server_socket.listen(5)
    try:
        while True:
            client_conn, client_addr = server_socket.accept()
            thread.start_new_thread(on_new_client, (client_conn, client_addr[0]))
    finally:
        server_socket.close()


if __name__ == '__main__':
    # Location of server private key file and channel list file
    key_file = 'server_key.priv'
    channels_file = 'channels'
    # If this server has been initialized, load variables
    if os.path.exists(key_file):
        private_key = pickle.load(key_file).importKey()
        public_key = private_key.publickey()
        channels = pickle.load(channels_file)
    # If this is a new server, create variables
    else:
        private_key = RSA.generate(2048, Random.new().read)
        pickle.dump(private_key.exportKey(), key_file)
        public_key = private_key.publickey()
        channels = {}  # Key == Channel Name, Value == List of Connections
    # Start channel thread
    main()

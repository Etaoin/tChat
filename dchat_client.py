import os, socket, pickle, hashlib, thread
from Crypto.PublicKey import RSA
from Crypto import Random


def listen(client_socket):
    while True:
        print private_key.decrypt(client_socket.recv(2048))


def main():
    # Connect to server
    server = (raw_input('Dchat Server Address: '), 9001)
    print '*** Connecting ***'
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(server)
    try:
        server_public_key = RSA.importKey(client_socket.recv(2048))  # Receive server's public key
        client_socket.sendall(public_key.exportKey())  # Send client's public key
        # All communications after this line are encrypted
        private_key_hash = hashlib.sha512(private_key.exportKey(format='PEM')).hexdigest()  # Hash client's private key
        client_socket.sendall(server_public_key.encrypt(private_key_hash))  # Send client's hashed private key
        print '*** Connected ***'
        # Attempt to connect to a channel
        while True:
            channel = raw_input('Channel: ').lower()
            client_socket.sendall(server_public_key.encrypt(channel))
            # If no channel, break
            if private_key.decrypt(client_socket.recv(2048)) == 'NO_CHANNEL':
                break
            # If there is a channel, join it if on whitelist
            else:
                thread.start_new_thread(listen, client_socket)
                while True:
                    msg = raw_input('> ')
                    client_socket.sendall(server_public_key.encrypt(msg))
    finally:
        client_socket.close()


# Initialization
if __name__ == '__main__':
    key_file = 'client_key.priv'
    if os.path.exists(key_file):
        private_key = pickle.load(key_file).importKey()
        public_key = private_key.publickey()
    else:
        random_gen = Random.new().read
        private_key = RSA.generate(2048, random_gen)
        pickle.dump(private_key.exportKey(), key_file)
        public_key = private_key.publickey()
    main()

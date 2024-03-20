#!/usr/bin/env python3

import socket
import argparse
import concurrent.futures
import hashlib
import os
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

args = argparse.ArgumentParser(description="Chat server")
args.add_argument("addr", action="store", help="IP address")
args.add_argument("port", type=int, action="store", help="Port")
args_dict = vars(args.parse_args())


class Server:

    def __init__(self):
        self.clients = {}
        self.user_keys = {}

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((args_dict["addr"], args_dict["port"]))
        self.sock.listen(100)

    def identify_client(self, conn):
        conn.send(b"Send user_id")
        user_id = conn.recv(256)
        return user_id.decode()

    def authenticate_user(self, conn, user_id):
        conn.send(b"Send public key")
        public_key_bytes = conn.recv(4096)
        if hashlib.sha256(public_key_bytes).hexdigest() != user_id:
            conn.send(b"Public key does not match user id")

        public_key = serialization.load_pem_public_key(public_key_bytes)
        challenge = hashlib.sha256(os.urandom(1024)).hexdigest().encode()
        ciphertext = public_key.encrypt(
            challenge,
            padding.OAEP(padding.MGF1(algorithm=hashes.SHA256()),
                         hashes.SHA256(), None))
        conn.send(ciphertext)
        if conn.recv(256) == challenge:
            conn.send(b"User authenticated")
            return public_key_bytes
        else:
            conn.send(b"Authentication challenge failed")
            return None

    def command_handler(self, string, sender):
        if string[0:8] == "!SENDKEY":
            user_id = string[9:]
            self.clients[sender].send(self.user_keys[user_id])

    def route_message(self, msg):
        msg_obj = json.loads(msg)
        dest_conn = self.clients[msg_obj["dest"]["val"]]
        dest_conn.send(msg)

    def client_handler(self, user_id, addr):
        conn = self.clients[user_id]

        while True:
            try:
                msg = conn.recv(4096)
                if msg:
                    print(f"<{addr[0]}> {msg}")
                    if msg.decode()[0] == "!":
                        self.command_handler(msg.decode(), user_id)
                    else:
                        self.route_message(msg)
                else:
                    del self.clients[user_id]
            except:
                continue

    def execute(self):
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = []
            while True:
                conn, addr = self.sock.accept()
                user_id = self.identify_client(conn)
                public_key = self.authenticate_user(conn, user_id)
                self.clients[user_id] = conn
                self.user_keys[user_id] = public_key
                print(f"{addr[0]} connected with id {user_id}")
                futures.append(
                    executor.submit(self.client_handler,
                                    user_id=user_id,
                                    addr=addr))


if __name__ == "__main__":
    ser = Server()
    ser.execute()

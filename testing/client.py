#!/usr/bin/env python3

import socket
import select
import sys
import argparse
import json
import ssl

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

args = argparse.ArgumentParser(description="Chat client")
args.add_argument("addr", action="store", help="IP address")
args.add_argument("port", type=int, action="store", help="Port")
args_dict = vars(args.parse_args())


class Client:

    def __init__(self):
        print("Enter user id")
        user_id = sys.stdin.readline().strip()
        print("Enter private key password")
        keypass = sys.stdin.readline().strip()
        with open(f"{user_id}_private.pem", "rb") as keyfile:
            self.private_key = serialization.load_pem_private_key(
                keyfile.read(), password=keypass.encode())

        with open(f"{user_id}_public.pem", "rb") as keyfile:
            self.public_key = serialization.load_pem_public_key(keyfile.read())

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.ssock = self.context.wrap_socket(self.server)
        self.ssock.connect((args_dict["addr"], args_dict["port"]))

        if self.ssock.recv(256) == b"Send user_id":
            self.ssock.send(user_id.encode())
        else:
            print("Client registration protocol violation. Exiting.")
            sys.exit()
        if self.ssock.recv(256) == b"Send public key":
            self.ssock.send(
                self.public_key.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo))
        else:
            print("Client registration protocol violation. Exiting.")
            sys.exit()

        challenge_ciphertext = self.ssock.recv(4096)
        challenge = self.private_key.decrypt(
            challenge_ciphertext,
            padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
        self.ssock.send(challenge)
        if self.ssock.recv(256) == b"User authenticated":
            print("Authenticated")
        else:
            print("Client registration protocol violation. Exiting.")
            sys.exit()

        self.state = {"dest": None}

    def command_handler(self, string):
        if string[0:12] == "!DESTINATION":
            self.state["dest"] = string[13:]

    def send_message(self, string):
        message = {"dest": self.state["dest"], "text": string}
        self.ssock.send(json.dumps(message).encode())

    def execute(self):
        while True:
            read_sock, write_sock, err_sock = select.select(
                [sys.stdin, self.ssock], [], [])
            for sock in read_sock:
                if sock == self.ssock:
                    msg = sock.recv(4096)
                    print(msg)
                else:
                    msg = sys.stdin.readline().strip()
                    if msg[0] == "!":
                        self.command_handler(msg)
                    else:
                        self.send_message(msg)
                    sys.stdout.write(f"<You> {msg}")
                    sys.stdout.flush()


if __name__ == "__main__":
    client = Client()
    client.execute()

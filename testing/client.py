#!/usr/bin/env python3

import socket
import select
import sys
import argparse
import json
import base64

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
        self.user_id = sys.stdin.readline().strip()
        print("Enter private key password")
        keypass = sys.stdin.readline().strip()
        with open(f"{self.user_id}_private.pem", "rb") as keyfile:
            self.private_key = serialization.load_pem_private_key(
                keyfile.read(), password=keypass.encode())

        with open(f"{self.user_id}_public.pem", "rb") as keyfile:
            self.public_key = serialization.load_pem_public_key(keyfile.read())

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.connect((args_dict["addr"], args_dict["port"]))

        if self.server.recv(256) == b"Send user_id":
            self.server.send(self.user_id.encode())
        else:
            print("Client registration protocol violation. Exiting.")
            sys.exit()
        if self.server.recv(256) == b"Send public key":
            self.server.send(
                self.public_key.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo))
        else:
            print("Client registration protocol violation. Exiting.")
            sys.exit()

        challenge_ciphertext = self.server.recv(4096)
        challenge = self.private_key.decrypt(
            challenge_ciphertext,
            padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
        self.server.send(challenge)
        if self.server.recv(256) == b"User authenticated":
            print("Authenticated")
        else:
            print("Client registration protocol violation. Exiting.")
            sys.exit()

        self.state = {"msg_log": [], "dest": None, "keyring": {}}

    def command_handler(self, string):
        if string[0:12] == "!DESTINATION":
            self.state["dest"] = string[13:]
        if string[0:9] == "!WRITELOG":
            with open("message_log", "w+") as logfile:
                logfile.write("\n".join(self.state["msg_log"]))

    def load_user_key(self, user_id):
        self.server.send(f"!SENDKEY {user_id}".encode())
        key_bytes = self.server.recv(4096)
        key = serialization.load_pem_public_key(key_bytes)
        self.state["keyring"][user_id] = key
        return key

    def send_message(self, string):
        if not self.state["dest"]:
            print("Cannot send message. No destination set.")
            return

        if not self.state["dest"] in self.state["keyring"]:
            destination_key = self.load_user_key(self.state["dest"])
        else:
            destination_key = self.state["keyring"][self.state["dest"]]

        ciphertext = destination_key.encrypt(
            string.encode(),
            padding.OAEP(padding.MGF1(algorithm=hashes.SHA256()),
                         hashes.SHA256(), None))
        ciphertext_b64_str = base64.b64encode(ciphertext).decode()

        message = json.dumps({
            "dest": self.state["dest"],
            "text": ciphertext_b64_str
        })
        self.state["msg_log"].append(message)
        self.server.send(message.encode())

    def receive_message(self, string):
        ciphertext = base64.b64decode(string)
        message_text = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(),
                         None)).decode()
        self.state["msg_log"].append(message_text)
        print(message_text)

    def execute(self):
        while True:
            read_sock, write_sock, err_sock = select.select(
                [sys.stdin, self.server], [], [])
            for sock in read_sock:
                if sock == self.server:
                    msg = sock.recv(4096)
                    self.receive_message(msg)
                else:
                    msg = sys.stdin.readline().strip()
                    if msg[0] == "!":
                        self.command_handler(msg)
                    else:
                        self.send_message(msg)


if __name__ == "__main__":
    client = Client()
    client.execute()

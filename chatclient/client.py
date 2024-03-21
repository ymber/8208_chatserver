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
from cryptography.exceptions import InvalidSignature

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
        if string.split()[0] == "!DESTINATION":
            self.state["dest"] = string.split()[1]
        if string.split()[0] == "!WRITELOG":
            with open("message_log", "w+") as logfile:
                logfile.write("\n".join(self.state["msg_log"]))
        if string.split()[0] == "!SENDFILE":
            with open(string.split()[1], "rb") as file:
                file_data = base64.b64encode(file.read()).decode()
                self.send_message(f"!FILE{file_data}")

    def load_user_key(self, user_id):
        self.server.send(f"!SENDKEY {user_id}".encode())
        key_bytes = self.server.recv(4096)
        key = serialization.load_pem_public_key(key_bytes)
        self.state["keyring"][user_id] = key
        return key

    def sign_message(self, msg_obj):
        sig_origin = self.private_key.sign(
            msg_obj["origin"].encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

        sig_dest = self.private_key.sign(
            msg_obj["dest"].encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

        sig_ciphertext = self.private_key.sign(
            msg_obj["text"].encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

        signed_msg = {
            "origin": {
                "sig": base64.b64encode(sig_origin).decode(),
                "val": msg_obj["origin"]
            },
            "dest": {
                "sig": base64.b64encode(sig_dest).decode(),
                "val": msg_obj["dest"]
            },
            "text": {
                "sig": base64.b64encode(sig_ciphertext).decode(),
                "val": msg_obj["text"]
            }
        }

        return signed_msg

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

        message = {
            "origin": self.user_id,
            "dest": self.state["dest"],
            "text": ciphertext_b64_str
        }

        signed_msg = json.dumps(self.sign_message(message))

        self.state["msg_log"].append(json.dumps(message))
        self.server.send(signed_msg.encode())

    def verify_signatures(self, msg):
        if not msg["origin"]["val"] in self.state["keyring"]:
            key = self.load_user_key(msg["origin"]["val"])
        else:
            key = self.state["keyring"][msg["origin"]["val"]]

        try:
            origin_sig_bytes = base64.b64decode(msg["origin"]["sig"])
            key.verify(
                origin_sig_bytes, msg["origin"]["val"].encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256())

            dest_sig_bytes = base64.b64decode(msg["dest"]["sig"])
            key.verify(
                dest_sig_bytes, msg["dest"]["val"].encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256())

            text_sig_bytes = base64.b64decode(msg["text"]["sig"])
            key.verify(
                text_sig_bytes, msg["text"]["val"].encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256())

        except InvalidSignature:
            return False

        return True

    def receive_message(self, string):
        msg_obj = json.loads(string)
        if self.verify_signatures(msg_obj) == False:
            print("Invalid signature")
            return

        ciphertext = base64.b64decode(msg_obj["text"]["val"])
        message_text = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(),
                         None)).decode()

        if message_text[0:5] == "!FILE":
            file_data = base64.b64decode(message_text[5:])
            with open("fname", "wb+") as file:
                file.write(file_data)
        else:
            out_string = f"<{msg_obj['origin']['val']}> {message_text}"
            self.state["msg_log"].append(out_string)
            print(out_string)

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

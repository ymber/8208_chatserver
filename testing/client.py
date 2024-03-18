#!/usr/bin/env python3

import socket
import select
import sys
import argparse

from cryptography.hazmat.primitives import serialization

args = argparse.ArgumentParser(description="server")
args.add_argument("addr", action="store", help="ip address")
args.add_argument("port", type=int, action="store", help="port")
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
        self.server.connect((args_dict["addr"], args_dict["port"]))
        if self.server.recv(256) == b"Send user_id":
            self.server.send(user_id.encode())

    def execute(self):
        while True:
            read_sock, write_sock, err_sock = select.select(
                [sys.stdin, self.server], [], [])
            for sock in read_sock:
                if sock == self.server:
                    msg = sock.recv(4096)
                    print(msg)
                else:
                    msg = sys.stdin.readline()
                    self.server.send(msg.encode())
                    sys.stdout.write(f"<You> {msg}")
                    sys.stdout.flush()


if __name__ == "__main__":
    client = Client()
    client.execute()

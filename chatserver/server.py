#!/usr/bin/env python3

import socket
import argparse
import concurrent.futures

args = argparse.ArgumentParser(description="server")
args.add_argument("addr", action="store", help="ip address")
args.add_argument("port", type=int, action="store", help="port")
args_dict = vars(args.parse_args())


class Server:

    def __init__(self):
        self.clients = {}

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((args_dict["addr"], args_dict["port"]))
        self.sock.listen(100)

    def identify_client(self, conn):
        conn.send(b"Send user_id")
        user_id = conn.recv(256)
        return user_id.decode()

    def broadcast(self, user_id, msg):
        for uid in self.clients:
            if uid != user_id:
                try:
                    self.clients[user_id].send(msg.encode())
                except:
                    self.clients[user_id].close()
                    del self.clients[user_id]

    def client_handler(self, user_id, addr):
        conn = self.clients[user_id]
        conn.send("Connection established".encode())

        while True:
            try:
                msg = conn.recv(4096)
                if msg:
                    print(f"<{addr[0]}> {msg}")
                    self.broadcast(user_id, f"<{addr[0]}> {msg}")
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
                self.clients[user_id] = conn
                print(f"{addr[0]} connected with id {user_id}")
                futures.append(
                    executor.submit(self.client_handler, user_id=user_id, addr=addr))


if __name__ == "__main__":
    ser = Server()
    ser.execute()

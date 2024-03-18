#!/usr/bin/env python3

import hashlib
import os
import argparse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

args = argparse.ArgumentParser(description="user generation script")
args.add_argument("number",
                  type=int,
                  action="store",
                  help="number of users to generate")
args.add_argument("password",
                  type=str,
                  action="store",
                  help="Password for encrypted private keys")
args_dict = vars(args.parse_args())

for i in range(0, args_dict["number"]):
    key = rsa.generate_private_key(65537, 4096)
    user_id = hashlib.sha256(key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    password_hash = hashlib.pbkdf2_hmac("sha256", args_dict["password"].encode(), os.urandom(16),
                                        600000).hex()

    with open(f"{user_id}_private.pem", "w") as file:
        file.write(
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(
                    password_hash.encode())).decode())

    with open(f"{user_id}_public.pem", "w") as file:
        file.write(key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode())

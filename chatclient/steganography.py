#!/usr/bin/env python3

import argparse
import cv2
import base64
import sys
import random

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

args = argparse.ArgumentParser(description="Steganography script")
args.add_argument("operation",
                  type=str,
                  action="store",
                  help="Mode of operation. Must be one of encode or decode.")
args.add_argument("file", type=str, action="store", help="File to operate on.")
args.add_argument("keyfile",
                  type=str,
                  action="store",
                  help="Public key to encrypt message with.")
args.add_argument("type",
                  type=str,
                  action="store",
                  help="File type. Must be one of image, mp3, mp4.")
args.add_argument("message",
                  nargs="?",
                  type=str,
                  action="store",
                  help="Message to encode. Must be provided in encode mode.")
args_dict = vars(args.parse_args())


class Steganography:

    def __init__(self):
        self.marker = b'\xff\x00\x00\xff'

    def hide_message_in_image(self, image_path, message):
        img = cv2.imread(image_path)

        binary_message = ''.join(
            format(byte, '08b') for byte in message.encode('utf-8'))
        binary_message += '1111111111111110'

        if len(binary_message) > img.size * 3:
            raise ValueError("Message too large.")

        data_index = 0

        random_bits = []

        for i in range(img.shape[0]):
            for j in range(img.shape[1]):
                for k in range(img.shape[2]):
                    if data_index < len(binary_message):
                        random_bit = random.randint(0, 1)
                        random_bits.append(random_bit) 
                        lsb = int(binary_message[data_index]) ^ random_bit
                        img[i, j, k] = (img[i, j, k] & ~1) | lsb
                        data_index += 1
                    else:
                        break
                else:
                    continue
                break
            else:
                continue
            break

        cv2.imwrite("stego_image.png", img)

        return random_bits

    def extract_message_from_image(self, image_path, random_bits):
        img = cv2.imread(image_path)

        binary_message = ''

        random_bits_index = 0

        for i in range(img.shape[0]):
            for j in range(img.shape[1]):
                for k in range(img.shape[2]):
                    extracted_lsb = img[i, j, k] & 1
                    random_bit = random_bits[random_bits_index]
                    extracted_lsb ^= random_bit
                    binary_message += str(extracted_lsb)

                    if binary_message[-16:] == '1111111111111110':
                        break
                    random_bits_index += 1
                else:
                    continue
                break
            else:
                continue
            break

        binary_message = binary_message[:-16]

        message = int(binary_message, 2).to_bytes(
            (len(binary_message) + 7) // 8, byteorder='big')

        return message

    def hide_message_in_mp3(self, mp3_path, message):
        with open(mp3_path, "rb") as file:
            mp3_data = bytearray(file.read())

        binary_message = ''.join(
            format(byte, '08b') for byte in message.encode('utf-8'))
        binary_message += '1111111111111110'

        if len(binary_message) > len(mp3_data):
            raise ValueError("Message too large to hide in MP3 file.")

        data_index = 0

        for i in range(len(mp3_data)):
            if data_index < len(binary_message):
                mp3_data[i] = (mp3_data[i] & ~1) | int(
                    binary_message[data_index])
                data_index += 1
            else:
                break

        with open("stego_audio.mp3", "wb") as file:
            file.write(mp3_data)

    def extract_message_from_mp3(self, mp3_path):
        with open(mp3_path, "rb") as file:
            mp3_data = file.read()

        binary_message = ''
        for byte in mp3_data:
            binary_message += str(byte & 1)

            if binary_message[-16:] == '1111111111111110':
                break

        binary_message = binary_message[:-16]

        message = int(binary_message, 2).to_bytes(
            (len(binary_message) + 7) // 8, byteorder='big')

        return message

    def hide_message_in_mp4(self, mp4_path, message):
        with open(mp4_path, "rb") as f:
            mp4_data = f.read()

        mp4_data = mp4_data + self.marker + message.encode('utf-8')

        with open("stego_video.mp4", "wb") as f:
            f.write(mp4_data)

    def extract_message_from_mp4(self, mp4_path):
        with open(mp4_path, "rb") as f:
            mp4_data = f.read()

        start_index = mp4_data.find(self.marker)

        if start_index == -1:
            raise ValueError("Marker not found in MP4 file.")

        message = mp4_data[start_index + len(self.marker):]

        return message


if __name__ == "__main__":
    steg = Steganography()

    if args_dict["operation"] == "encode":
        encoders = {
            "image": steg.hide_message_in_image,
            "mp3": steg.hide_message_in_mp3,
            "mp4": steg.hide_message_in_mp4
        }
        with open(args_dict["keyfile"], "rb") as keyfile:
            key = serialization.load_pem_public_key(keyfile.read())
            ciphertext = key.encrypt(
                args_dict["message"].encode(),
                padding.OAEP(padding.MGF1(algorithm=hashes.SHA256()),
                             hashes.SHA256(), None))
            ciphertext_b64_str = base64.b64encode(ciphertext).decode()

            encoders[args_dict["type"]](args_dict["file"], ciphertext_b64_str)
            random_bits = encoders[args_dict["type"]](args_dict["file"], ciphertext_b64_str)

    elif args_dict["operation"] == "decode":
        decoders = {
            "image": steg.extract_message_from_image,
            "mp3": steg.extract_message_from_mp3,
            "mp4": steg.extract_message_from_mp4
        }
        with open(args_dict["keyfile"], "rb") as keyfile:
            print("Enter private key password")
            keypass = sys.stdin.readline().strip()
            key = serialization.load_pem_private_key(keyfile.read(),
                                                     password=keypass.encode())
            ciphertext_b64_str = decoders[args_dict["type"]](args_dict["file"])
            ciphertext = base64.b64decode(ciphertext_b64_str)
            message = key.decrypt(
                ciphertext,
                padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(),
                             None)).decode()
            print(message)

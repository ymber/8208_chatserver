from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hmac
import hashlib
import secrets
import cv2

class Steganography:
    def __init__(self):
        self.private_key, self.public_key = self.generate_key_pair()
        self.hmac_key = secrets.token_bytes(32)
        self.marker = b'\xff\x00\x00\xff'

    def generate_key_pair(self):
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        return private_key, public_key

    def encrypt_message(self, public_key, message):
        cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
        encrypted_message = cipher.encrypt(message.encode())

        return encrypted_message

    def decrypt_message(self, encrypted_message):
        cipher = PKCS1_OAEP.new(RSA.import_key(self.private_key))
        decrypted_message = cipher.decrypt(encrypted_message)

        return decrypted_message

    def add_hmac(self, encrypted_message):
        hmac_digest = hmac.new(self.hmac_key, encrypted_message, hashlib.sha256).digest()

        return encrypted_message + hmac_digest

    def extract_message(self, encrypted_data):
        hmac_digest = encrypted_data[-32:]
        encrypted_message = encrypted_data[:-32]
        computed_hmac = hmac.new(self.hmac_key, encrypted_message, hashlib.sha256).digest()

        if hmac.compare_digest(hmac_digest, computed_hmac):
            return self.decrypt_message(encrypted_message)
        else:
            raise ValueError("HMAC verification failed.")

    def hide_message_in_image(self, image_path, message):
        img = cv2.imread(image_path)

        encrypted_message = self.encrypt_message(self.public_key, message)
        encrypted_message_with_hmac = self.add_hmac(encrypted_message)
        binary_message = ''.join(format(byte, '08b') for byte in encrypted_message_with_hmac)
        binary_message += '1111111111111110'

        if len(binary_message) > img.size * 3:
            raise ValueError("Message too large.")

        data_index = 0

        for i in range(img.shape[0]):
            for j in range(img.shape[1]):
                for k in range(img.shape[2]):
                    if data_index < len(binary_message):
                        img[i, j, k] = (img[i, j, k] & ~1) | int(binary_message[data_index])
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

    def extract_message_from_image(self, image_path):
        img = cv2.imread(image_path)

        binary_message = ''

        for i in range(img.shape[0]):
            for j in range(img.shape[1]):
                for k in range(img.shape[2]):
                    binary_message += str(img[i, j, k] & 1)

                    if binary_message[-16:] == '1111111111111110':
                        break
                else:
                    continue
                break
            else:
                continue
            break

        binary_message = binary_message[:-16]

        encrypted_message_with_hmac = int(binary_message, 2).to_bytes((len(binary_message) + 7) // 8, byteorder='big')
        extracted_message = self.extract_message(encrypted_message_with_hmac)

        return extracted_message
    
    def hide_message_in_mp3(self, mp3_path, message):
        with open(mp3_path, "rb") as file:
            mp3_data = bytearray(file.read())

        encrypted_message = self.encrypt_message(self.public_key, message)
        encrypted_message_with_hmac = self.add_hmac(encrypted_message)

        binary_message = ''.join(format(byte, '08b') for byte in encrypted_message_with_hmac)
        binary_message += '1111111111111110'

        if len(binary_message) > len(mp3_data):
            raise ValueError("Message too large to hide in MP3 file.")

        data_index = 0

        for i in range(len(mp3_data)):
            if data_index < len(binary_message):
                mp3_data[i] = (mp3_data[i] & ~1) | int(binary_message[data_index])
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

        encrypted_message_with_hmac = int(binary_message, 2).to_bytes((len(binary_message) + 7) // 8, byteorder='big')
        extracted_message = self.extract_message(encrypted_message_with_hmac)

        return extracted_message
    
    def hide_message_in_mp4(self, mp4_path, message):
        with open(mp4_path, "rb") as f:
            mp4_data = f.read()

        encrypted_message = self.encrypt_message(self.public_key, message)
        encrypted_message_with_hmac = self.add_hmac(encrypted_message)

        mp4_data = mp4_data + self.marker + encrypted_message_with_hmac

        with open("stego_video.mp4", "wb") as f:
            f.write(mp4_data)

    def extract_message_from_mp4(self, mp4_path):
        with open(mp4_path, "rb") as f:
            mp4_data = f.read()

        start_index = mp4_data.find(self.marker)

        if start_index == -1:
            raise ValueError("Marker not found in MP4 file.")

        encrypted_message_with_hmac = mp4_data[start_index + len(self.marker):]
        extracted_message = self.extract_message(encrypted_message_with_hmac)

        return extracted_message
    
message = "Test message."

steg = Steganography()

steg.hide_message_in_image("test.png", message)
extracted_message = steg.extract_message_from_image("stego_image.png")

# steg.hide_message_in_mp3("test.mp3", message)
# extracted_message = steg.extract_message_from_mp3("stego_audio.mp3")

# steg.hide_message_in_mp4("test.mp4", message)
# extracted_message = steg.extract_message_from_mp4("stego_video.mp4")

print("Extracted message:", extracted_message.decode())

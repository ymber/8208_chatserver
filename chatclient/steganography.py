import cv2

class Steganography:
    def __init__(self):
        self.marker = b'\xff\x00\x00\xff'

    def hide_message_in_image(self, image_path, message):
        img = cv2.imread(image_path)

        binary_message = ''.join(format(byte, '08b') for byte in message.encode('utf-8'))
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

        message = int(binary_message, 2).to_bytes((len(binary_message) + 7) // 8, byteorder='big')

        return message
    
    def hide_message_in_mp3(self, mp3_path, message):
        with open(mp3_path, "rb") as file:
            mp3_data = bytearray(file.read())

        binary_message = ''.join(format(byte, '08b') for byte in message.encode('utf-8'))
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

        message = int(binary_message, 2).to_bytes((len(binary_message) + 7) // 8, byteorder='big')

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

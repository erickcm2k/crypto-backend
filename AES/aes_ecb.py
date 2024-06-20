from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def encrypt_image_ecb(key, input_file):
    with open(input_file, 'rb') as f:
        header = f.read(54)  # Lee la cabecera de 54 bytes
        plaintext = f.read()

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    output_file = os.path.splitext(input_file)[0] + "_cECB.bmp"
    with open(output_file, 'wb') as f:
        f.write(header)  # Escribe la cabecera sin cifrar
        f.write(ciphertext)

def decrypt_image_ecb(key, input_file):
    with open(input_file, 'rb') as f:
        header = f.read(54)  # Lee la cabecera de 54 bytes
        ciphertext = f.read()

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    output_file = os.path.splitext(input_file)[0] + "_dECB.bmp"
    with open(output_file, 'wb') as f:
        f.write(header)  # Escribe la cabecera sin cifrar
        f.write(unpadded_data)

# Ejemplo de uso
key = os.urandom(16)  # Clave AES de 128 bits

input_image = input("Ingrese el nombre del archivo de imagen BMP: ")

encrypt_image_ecb(key, input_image)
decrypt_image_ecb(key, os.path.splitext(input_image)[0] + "_cECB.bmp")

print("Proceso completado.")

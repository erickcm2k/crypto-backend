from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def encrypt_image_cfb(key, iv, input_file):
    with open(input_file, 'rb') as f:
        header = f.read(54)  # Lee la cabecera de 54 bytes
        plaintext = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    output_file = os.path.splitext(input_file)[0] + "_cCFB.bmp"
    with open(output_file, 'wb') as f:
        f.write(header)  # Escribe la cabecera sin cifrar
        f.write(iv + ciphertext)

def decrypt_image_cfb(key, iv, input_file):
    with open(input_file, 'rb') as f:
        header = f.read(54)  # Lee la cabecera de 54 bytes
        iv_ciphertext = f.read()

    iv = iv_ciphertext[:len(iv)]
    ciphertext = iv_ciphertext[len(iv):]

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    output_file = os.path.splitext(input_file)[0] + "_dCFB.bmp"
    with open(output_file, 'wb') as f:
        f.write(header)  # Escribe la cabecera sin cifrar
        f.write(decrypted_data)

# Ejemplo de uso
key = os.urandom(16)  # Clave AES de 256 bits
iv = os.urandom(16)   # Vector de inicialización (IV) de 16 bytes

input_image = input("Ingrese el nombre del archivo de imagen BMP: ")

encrypt_image_cfb(key, iv, input_image)
decrypt_image_cfb(key, iv, os.path.splitext(input_image)[0] + "_cCFB.bmp")

print("Proceso completado.")

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

def generar_llaves():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Serializar y guardar las llaves en archivos .key
    with open("private_rsa.key", "wb") as priv_file:
        priv_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("public_rsa.key", "wb") as pub_file:
        pub_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    return "private_rsa.key", "public_rsa.key"

def encrypt(llave_publica, archivo_a_cifrar):
    # Leer la clave pública desde el archivo
    with open(llave_publica, "rb") as pub_file:
        public_key = serialization.load_pem_public_key(
            pub_file.read(),
            backend=default_backend()
        )

    # Leer el archivo que contiene la clave AES y el IV
    with open(archivo_a_cifrar, "r") as f:
        aes_key = f.readline().strip()
        iv = f.readline().strip()

    # Convertir la clave AES y el IV a bytes
    aes_key_bytes = base64.b64decode(aes_key)
    iv_bytes = base64.b64decode(iv)

    # Cifrar la clave AES y el IV usando la clave pública RSA
    encrypted_aes_key = public_key.encrypt(
        aes_key_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encrypted_iv = public_key.encrypt(
        iv_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Guardar la longitud de la clave AES cifrada
    aes_key_length = len(encrypted_aes_key)

    # Guardar el texto cifrado en un archivo .txt
    with open("E(K_AES).txt", "wb") as f:
        f.write(aes_key_length.to_bytes(4, 'big') + encrypted_aes_key + encrypted_iv)

    print("Cifrado completado y guardado en E(K_AES).txt")
    return "E(K_AES).txt"

def decrypt(llave_privada, archivo_cifrado):
    # Leer la clave privada desde el archivo
    with open(llave_privada, "rb") as priv_file:
        private_key = serialization.load_pem_private_key(
            priv_file.read(),
            password=None,
            backend=default_backend()
        )

    # Leer el archivo cifrado
    with open(archivo_cifrado, "rb") as enc_file:
        encrypted_data = enc_file.read()

    # Obtener la longitud de la clave AES cifrada
    aes_key_length = int.from_bytes(encrypted_data[:4], 'big')

    # Separar los datos cifrados de la clave AES y el IV
    encrypted_aes_key = encrypted_data[4:4 + aes_key_length]
    encrypted_iv = encrypted_data[4 + aes_key_length:]

    # Descifrar la clave AES usando la clave privada RSA
    aes_key_bytes = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Descifrar el IV usando la clave privada RSA
    iv_bytes = private_key.decrypt(
        encrypted_iv,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Convertir la clave AES y el IV a base64 para guardarlos en un archivo
    aes_key_base64 = base64.b64encode(aes_key_bytes).decode('utf-8')
    iv_base64 = base64.b64encode(iv_bytes).decode('utf-8')

    # Guardar la clave AES y el IV en un archivo txt
    with open("K_AES.txt", "w") as f:
        f.write(aes_key_base64 + '\n' + iv_base64)

    print("Descifrado completado y guardado en K_AES.txt")
    return "K_AES.txt"

# Ejemplo de uso
# Generar llaves
private_key_file, public_key_file = generar_llaves()

# Cifrar
archivo_cifrado = encrypt(public_key_file, "aes_key_iv.txt")

# Descifrar
archivo_descifrado = decrypt(private_key_file, archivo_cifrado)

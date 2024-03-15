from flask import Flask, request, Response, jsonify
from flask_cors import CORS
import base64
from cryptography.fernet import Fernet

app = Flask(__name__)
CORS(app)

def es_base64(cadena):
    try:
        # Intenta decodificar la cadena Base64
        base64.decodebytes(cadena.encode('utf-8'))
        return True
    except binascii.Error:
        # Si la cadena no está en Base64 válido, se genera un error
        return False

@app.route('/key', methods=['GET'])
def generate_key():
    response = Response(Fernet.generate_key(), content_type='text/plain')
    response.headers.set('Content-Disposition', 'attachment', filename='llave.key')    
    return response

@app.route('/encrypt', methods=['POST'])
def encrypt():         
    try:
        key_file = request.files['keyFile'] 
        file_content = request.files['fileContent']
        
        # Extraer el contenido de los archivos
        file_content_text = file_content.read().decode('utf-8')
        key_file_text = key_file.read().decode('utf-8')

        # Convertir contenido de la llave a binario
        file_content_binary = bytes(file_content_text,'utf-8')
        
        # Cifrado de mensaje
        fernet = Fernet(key_file_text)
        encryptedMsg = fernet.encrypt(file_content_binary)

        # Se retorna un archivo de texto con el mensaje cifrado
        response = Response(encryptedMsg, content_type='text/plain')
        response.headers.set('Content-Disposition', 'attachment', filename=f'file.txt') 
        
        return response     
        
    except:
        response = jsonify({"resultado": "Operación fallida"})
        response.status_code = 400
        return response
        


@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        key_file = request.files['keyFile'] 
        file_content = request.files['fileContent']

        # Extraer el contenido de los archivos
        file_content_text = file_content.read().decode('utf-8')
        key_file_text = key_file.read().decode('utf-8')

        # Convertir contenido de la llave a binario
        file_content_binary = bytes(file_content_text,'utf-8')       
        
        fernet = Fernet(key_file_text)
        decripted_msg = fernet.decrypt(file_content_binary)

        # Se retorna un archivo de texto con el mensaje descifrado
        response = Response(decripted_msg, content_type='text/plain')
        response.headers.set('Content-Disposition', 'attachment', filename='file.txt')     
        
        return response    
    except:
        response = jsonify({"resultado": "Operación fallida"})
        response.status_code = 400
        return response
        

if __name__ == "__main__":
    app.run(debug=True)
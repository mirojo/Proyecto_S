from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import os
import json
import time
import uuid

# Generar claves RSA
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Serializar clave pública
def serialize_public_key(public_key):
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Cifrar con clave pública
def rsa_encrypt(public_key, message):
    return public_key.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

# Descifrar con clave privada
def rsa_decrypt(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

# Firmar mensaje
def sign(private_key, message_bytes):
    return private_key.sign(
        message_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

# Verificar firma
def verify(public_key, signature, message_bytes):
    try:
        public_key.verify(signature, message_bytes, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return True
    except:
        return False

# Generar clave AES
def generate_aes_key():
    return os.urandom(32)  # 256 bits

# Cifrar con AES-CBC
def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext  # concatenar iv para descifrado

# Descifrar con AES-CBC
def aes_decrypt(key, ciphertext):
    iv = ciphertext[:16]
    actual_ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(actual_ct) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext

# Simular envío de mensaje cifrado por canal
def send_encrypted_message(aes_key, message_dict):
    message_bytes = json.dumps(message_dict).encode()
    return aes_encrypt(aes_key, message_bytes)

# Simular recepción y descifrado
def receive_encrypted_message(aes_key, encrypted_message):
    plaintext_bytes = aes_decrypt(aes_key, encrypted_message)
    return json.loads(plaintext_bytes.decode())

# IA Defensora inicia protocolo
def defender_protocol():
    # Generar claves RSA para defensor y atacante
    priv_def, pub_def = generate_rsa_keys()
    priv_att, pub_att = generate_rsa_keys()

    # Paso 1: IA Defensora crea mensaje de identificación
    id_message = {
        "uuid": str(uuid.uuid4()),
        "timestamp": int(time.time()),
        "intention": "IA Defensora iniciando protocolo de negociación"
    }
    id_msg_bytes = json.dumps(id_message).encode()
    signature_def = sign(priv_def, id_msg_bytes)

    # Enviar id_message + signature + clave pública defensor a IA Atacante
    # (simulado enviando variables)
    # IA Atacante verifica firma y responde

    # Verificar firma defensor
    if not verify(pub_def, signature_def, id_msg_bytes):
        print("Firma de IA Defensora inválida")
        return

    print("Firma de IA Defensora verificada")

    # IA Atacante genera clave AES para canal cifrado
    aes_key = generate_aes_key()

    # IA Atacante cifra clave AES con clave pública defensor y la envía
    encrypted_aes_key = rsa_encrypt(pub_def, aes_key)

    # IA Defensora descifra clave AES
    aes_key_def = rsa_decrypt(priv_def, encrypted_aes_key)

    # IA Atacante prepara mensaje cifrado con AES para responder
    att_response = {
        "uuid": str(uuid.uuid4()),
        "timestamp": int(time.time()),
        "intention": "IA Atacante respondiendo y estableciendo canal seguro"
    }
    att_response_encrypted = send_encrypted_message(aes_key, att_response)

    # IA Defensora recibe y descifra
    received_message = receive_encrypted_message(aes_key_def, att_response_encrypted)

    print("Mensaje recibido y descifrado en canal seguro:")
    print(received_message)

    # IA Defensora responde con mensaje cifrado y firmado dentro del canal seguro
    def_response = {
        "uuid": str(uuid.uuid4()),
        "timestamp": int(time.time()),
        "intention": "IA Defensora confirma canal seguro y disposición a negociar"
    }
    def_response_bytes = json.dumps(def_response).encode()
    def_signature = sign(priv_def, def_response_bytes)
    def_response_encrypted = send_encrypted_message(aes_key_def, {
        "message": def_response,
        "signature": def_signature.hex()
    })

    # IA Atacante recibe y verifica firma
    received_def_resp = receive_encrypted_message(aes_key, def_response_encrypted)
    message_bytes = json.dumps(received_def_resp["message"]).encode()
    signature_bytes = bytes.fromhex(received_def_resp["signature"])

    if verify(pub_def, signature_bytes, message_bytes):
        print("Firma de IA Defensora verificada dentro del canal seguro.")
        print("Protocolo de establecimiento de canal seguro completado con éxito.")
    else:
        print("Firma inválida en canal seguro.")

if __name__ == "__main__":
    defender_protocol()

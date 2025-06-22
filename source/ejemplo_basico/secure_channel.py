# secure_channel.py
import json
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.exceptions import InvalidSignature

class SecureChannel:
    def __init__(self):
        self._private_key = None
        self._public_key = None
        self._peer_public_key = None
        self._aes_key = None

    # Generar claves RSA propias
    def generate_rsa_keys(self):
        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._public_key = self._private_key.public_key()

    # Obtener la clave pública (para compartir)
    def get_public_key(self):
        return self._public_key

    # Establecer clave pública del peer
    def set_peer_public_key(self, peer_public_key):
        self._peer_public_key = peer_public_key

    # Firmar mensaje (bytes)
    def sign(self, message_bytes):
        return self._private_key.sign(
            message_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

    # Verificar firma (bytes)
    def verify(self, public_key, message_bytes, signature):
        try:
            public_key.verify(signature, message_bytes,
                              padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                              hashes.SHA256())
            return True
        except InvalidSignature:
            return False

    # Preparar mensaje firmado en JSON serializable
    def prepare_signed_message(self, message_dict):
        message_bytes = json.dumps(message_dict).encode()
        signature = self.sign(message_bytes)
        return {
            "message": message_dict,
            "signature": signature.hex()
        }

    # Verificar mensaje firmado
    def verify_signed_message(self, signed_message):
        message_bytes = json.dumps(signed_message["message"]).encode()
        signature = bytes.fromhex(signed_message["signature"])
        return self.verify(self._peer_public_key, message_bytes, signature), signed_message["message"]

    # Generar clave AES (simétrica)
    def generate_aes_key(self):
        self._aes_key = os.urandom(32)  # 256 bits
        return self._aes_key

    # Recibir clave AES cifrada con RSA y descifrar
    def decrypt_aes_key(self, encrypted_aes_key):
        self._aes_key = self._private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return self._aes_key

    # Cifrar mensaje con AES
    def aes_encrypt(self, plaintext_bytes):
        iv = os.urandom(16)
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext_bytes) + padder.finalize()
        cipher = Cipher(algorithms.AES(self._aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext

    # Descifrar mensaje con AES
    def aes_decrypt(self, ciphertext):
        iv = ciphertext[:16]
        actual_ct = ciphertext[16:]
        cipher = Cipher(algorithms.AES(self._aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(actual_ct) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext

    # Enviar mensaje: firmar y cifrar
    def send_encrypted(self, message_dict):
        signed_msg = self.prepare_signed_message(message_dict)
        plaintext = json.dumps(signed_msg).encode()
        return self.aes_encrypt(plaintext)

    # Recibir mensaje: descifrar y verificar firma
    def receive_encrypted(self, ciphertext):
        plaintext = self.aes_decrypt(ciphertext)
        signed_msg = json.loads(plaintext.decode())
        valid, msg = self.verify_signed_message(signed_msg)
        if not valid:
            raise ValueError("Firma inválida en mensaje cifrado.")
        return msg

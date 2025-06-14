import json
import time
import uuid
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.exceptions import InvalidSignature
import os

# --- Claves RSA ---
def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# --- Firmar y verificar ---
def sign_message(private_key, message_bytes):
    return private_key.sign(
        message_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def verify_signature(public_key, message_bytes, signature):
    try:
        public_key.verify(signature, message_bytes,
                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                          hashes.SHA256())
        return True
    except InvalidSignature:
        return False

# --- AES simétrico para canal cifrado ---
def generate_aes_key():
    return os.urandom(32)  # 256 bits

def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def aes_decrypt(key, ciphertext):
    iv = ciphertext[:16]
    actual_ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(actual_ct) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext

# --- Mensajes firmados ---
def prepare_signed_message(private_key, message_dict):
    message_bytes = json.dumps(message_dict).encode()
    signature = sign_message(private_key, message_bytes)
    return {
        "message": message_dict,
        "signature": signature.hex()
    }

def verify_signed_message(public_key, signed_message):
    message_bytes = json.dumps(signed_message["message"]).encode()
    signature = bytes.fromhex(signed_message["signature"])
    return verify_signature(public_key, message_bytes, signature), signed_message["message"]

# --- Simulación protocolo completo ---
def negotiation_protocol():
    # Generar claves
    priv_def, pub_def = generate_keys()
    priv_att, pub_att = generate_keys()

    print("Claves RSA generadas para ambas IAs.\n")

    # Paso 1: IA defensora inicia con mensaje firmado
    init_msg = {
        "uuid": str(uuid.uuid4()),
        "timestamp": int(time.time()),
        "intention": "Iniciar protocolo de negociación"
    }
    signed_init_msg = prepare_signed_message(priv_def, init_msg)
    print("IA Defensora envía mensaje inicial firmado.")

    # IA atacante verifica mensaje
    valid, received_msg = verify_signed_message(pub_def, signed_init_msg)
    if not valid:
        print("IA Atacante: Firma inválida en mensaje inicial. Abortando.")
        return
    print("IA Atacante: Mensaje inicial verificado correctamente.")

    # Paso 2: IA atacante genera clave AES para canal cifrado
    aes_key = generate_aes_key()
    # La IA atacante cifra la clave AES con clave pública defensora para enviarla (simulado)
    encrypted_aes_key = pub_def.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    # IA defensora descifra clave AES
    decrypted_aes_key = priv_def.decrypt(
        encrypted_aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    print("Clave AES para canal seguro intercambiada y establecida.\n")

    # Paso 3: Comunicación cifrada con AES y mensajes firmados
    def send_encrypted(symmetric_key, private_key, message_dict):
        signed_msg = prepare_signed_message(private_key, message_dict)
        plaintext = json.dumps(signed_msg).encode()
        return aes_encrypt(symmetric_key, plaintext)

    def receive_encrypted(symmetric_key, public_key, ciphertext):
        plaintext = aes_decrypt(symmetric_key, ciphertext)
        signed_msg = json.loads(plaintext.decode())
        valid, msg = verify_signed_message(public_key, signed_msg)
        if not valid:
            raise ValueError("Firma inválida en mensaje cifrado.")
        return msg

    # Paso 4: Ejemplo de negociación inicial cifrada
    negotiation_msg = {
        "uuid": str(uuid.uuid4()),
        "timestamp": int(time.time()),
        "intention": "Confirmación de canal seguro y disposición a negociar"
    }
    encrypted_msg = send_encrypted(decrypted_aes_key, priv_att, negotiation_msg)
    received_msg = receive_encrypted(decrypted_aes_key, pub_att, encrypted_msg)
    print("IA Defensora recibe mensaje cifrado y firmado:")
    print(received_msg, "\n")

    # Paso 5: Negociación - IA atacante propone escaneo de puertos
    attack_proposal = {
        "uuid": str(uuid.uuid4()),
        "timestamp": int(time.time()),
        "proposal": "Realizar escaneo de puertos en sistemas defensores"
    }
    encrypted_proposal = send_encrypted(decrypted_aes_key, priv_att, attack_proposal)

    # IA defensora recibe y analiza propuesta
    proposal_msg = receive_encrypted(decrypted_aes_key, pub_att, encrypted_proposal)
    print("IA Defensora recibe propuesta de ataque:")
    print(proposal_msg)

    # IA defensora responde con contrapropuesta
    counter_offer = {
        "uuid": str(uuid.uuid4()),
        "timestamp": int(time.time()),
        "response": "Ofrezco compartir datos de seguridad a cambio de no realizar escaneo"
    }
    encrypted_counter = send_encrypted(decrypted_aes_key, priv_def, counter_offer)

    # IA atacante recibe y verifica
    counter_msg = receive_encrypted(decrypted_aes_key, pub_def, encrypted_counter)
    print("\nIA Atacante recibe contrapropuesta:")
    print(counter_msg)

    print("\nNegociación inicial y propuesta de simbiosis completadas con éxito.")

if __name__ == "__main__":
    negotiation_protocol()

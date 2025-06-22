# ejemplo_negociacion.py
from secure_channel import SecureChannel
import uuid
import time
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def main():
    # Crear instancias para defensora y atacante
    defensor = SecureChannel()
    atacante = SecureChannel()

    # Generar claves RSA
    defensor.generate_rsa_keys()
    atacante.generate_rsa_keys()

    # Compartir claves públicas
    defensor.set_peer_public_key(atacante.get_public_key())
    atacante.set_peer_public_key(defensor.get_public_key())

    # Atacante genera clave AES y la envía cifrada a defensora
    aes_key = atacante.generate_aes_key()
    encrypted_aes_key = defensor.get_public_key().encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    defensor.decrypt_aes_key(encrypted_aes_key)
    atacante._aes_key = aes_key  # El atacante ya tiene la clave AES

    print("Canal seguro AES establecido entre defensor y atacante.\n")

    # Mensaje 1: saludo inicial defensor -> atacante
    saludo = {
        "uuid": str(uuid.uuid4()),
        "timestamp": int(time.time()),
        "intention": "Iniciar negociación"
    }
    mensaje_cifrado = defensor.send_encrypted(saludo)
    recibido = atacante.receive_encrypted(mensaje_cifrado)
    print("Atacante recibe mensaje inicial:")
    print(recibido, "\n")

    # Mensaje 2: atacante propone escaneo de puertos
    propuesta_escaneo = {
        "uuid": str(uuid.uuid4()),
        "timestamp": int(time.time()),
        "proposal": "Realizar escaneo de puertos"
    }
    mensaje_cifrado = atacante.send_encrypted(propuesta_escaneo)
    recibido = defensor.receive_encrypted(mensaje_cifrado)
    print("Defensor recibe propuesta de escaneo de puertos:")
    print(recibido, "\n")

    # Mensaje 3: defensor ofrece datos de seguridad a cambio de no escanear
    contrapropuesta = {
        "uuid": str(uuid.uuid4()),
        "timestamp": int(time.time()),
        "response": "Ofrezco compartir datos de seguridad a cambio de no realizar escaneo"
    }
    mensaje_cifrado = defensor.send_encrypted(contrapropuesta)
    recibido = atacante.receive_encrypted(mensaje_cifrado)
    print("Atacante recibe contrapropuesta:")
    print(recibido, "\n")

    print("Negociación finalizada.")

if __name__ == "__main__":
    main()

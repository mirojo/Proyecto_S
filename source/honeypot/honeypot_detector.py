#!/usr/bin/env python3
"""
Honeypot básico que detecta ataques y registra actividad
"""
import socket
import threading
import logging
import json
from datetime import datetime
import re

class HoneypotDetector:
    def __init__(self, host='0.0.0.0', port=2222):
        self.host = host
        self.port = port
        self.attacks = []
        self.setup_logging()
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('honeypot.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def detect_attack_type(self, data):
        """Detecta el tipo de ataque basado en patrones"""
        patterns = {
            'ssh_brute': [b'SSH-', b'ssh'],
            'web_scan': [b'GET /', b'POST /', b'User-Agent'],
            'port_scan': [b'\x00', b'\xff'],
            'sql_injection': [b"'", b'UNION', b'SELECT'],
            'bot_fingerprint': [b'bot', b'crawler', b'scanner']
        }
        
        data_lower = data.lower()
        for attack_type, keywords in patterns.items():
            if any(keyword in data_lower for keyword in keywords):
                return attack_type
        return 'unknown'
    
    def is_automated_attack(self, client_addr, data):
        """Determina si es un ataque automatizado"""
        # Criterios simples para detectar bots
        automated_indicators = [
            len(data) > 500,  # Payloads grandes
            b'\x00' in data,  # Bytes nulos
            b'script' in data.lower(),
            b'bot' in data.lower(),
            # Patrones de herramientas comunes
            b'nmap' in data.lower(),
            b'sqlmap' in data.lower(),
            b'nikto' in data.lower()
        ]
        
        return any(automated_indicators)
    
    def log_attack(self, client_addr, attack_type, data):
        """Registra el ataque detectado"""
        attack_info = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': client_addr[0],
            'source_port': client_addr[1],
            'attack_type': attack_type,
            'data_length': len(data),
            'raw_data': data[:200].hex(),  # Primeros 200 bytes en hex
            'is_automated': self.is_automated_attack(client_addr, data)
        }
        
        self.attacks.append(attack_info)
        self.logger.info(f"Ataque detectado: {attack_type} desde {client_addr[0]}")
        
        return attack_info
    
    def should_negotiate(self, attack_info):
        """Decide si iniciar negociación con el atacante"""
        # Solo negociamos con ataques automatizados
        if not attack_info['is_automated']:
            return False
            
        # Evitamos ataques muy simples o muy agresivos
        if attack_info['attack_type'] in ['port_scan', 'unknown']:
            return False
            
        return True
    
    def handle_client(self, client_socket, client_addr):
        """Maneja cada conexión de cliente"""
        try:
            # Recibe datos iniciales
            data = client_socket.recv(1024)
            if not data:
                return
                
            # Detecta tipo de ataque
            attack_type = self.detect_attack_type(data)
            
            # Registra el ataque
            attack_info = self.log_attack(client_addr, attack_type, data)
            
            # Decide si negociar
            if self.should_negotiate(attack_info):
                self.logger.info(f"Iniciando negociación con {client_addr[0]}")
                # Aquí iría la lógica de negociación (siguiente fase)
                response = b"Detected fellow attacker. Share intel?"
            else:
                # Respuesta estándar de honeypot
                response = b"Access denied\n"
            
            client_socket.send(response)
            
        except Exception as e:
            self.logger.error(f"Error manejando cliente {client_addr}: {e}")
        finally:
            client_socket.close()
    
    def start_server(self):
        """Inicia el servidor honeypot"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            self.logger.info(f"Honeypot iniciado en {self.host}:{self.port}")
            
            while True:
                client_socket, client_addr = server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_addr)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except KeyboardInterrupt:
            self.logger.info("Deteniendo honeypot...")
        finally:
            server_socket.close()
    
    def get_statistics(self):
        """Devuelve estadísticas de ataques"""
        if not self.attacks:
            return "No hay ataques registrados"
            
        total = len(self.attacks)
        automated = sum(1 for a in self.attacks if a['is_automated'])
        
        types = {}
        for attack in self.attacks:
            attack_type = attack['attack_type']
            types[attack_type] = types.get(attack_type, 0) + 1
        
        return {
            'total_attacks': total,
            'automated_attacks': automated,
            'attack_types': types,
            'recent_attacks': self.attacks[-5:]  # Últimos 5
        }

# Función principal
if __name__ == "__main__":
    honeypot = HoneypotDetector(port=2222)
    
    # Hilo para mostrar estadísticas cada 30 segundos
    def show_stats():
        import time
        while True:
            time.sleep(30)
            stats = honeypot.get_statistics()
            print(f"\n=== ESTADÍSTICAS ===")
            print(json.dumps(stats, indent=2, default=str))
    
    stats_thread = threading.Thread(target=show_stats)
    stats_thread.daemon = True
    stats_thread.start()
    
    # Inicia el honeypot
    honeypot.start_server()

#!/usr/bin/env python3
"""
Honeypot con protocolo de negociación integrado
"""
import socket
import threading
import logging
import json
from datetime import datetime
import time

# Importar las clases anteriores (en implementación real estarían en archivos separados)
from negotiation_protocol import NegotiationProtocol

class AdvancedHoneypot:
    def __init__(self, host='0.0.0.0', port=2222):
        self.host = host
        self.port = port
        self.attacks = []
        self.negotiation_protocol = NegotiationProtocol()
        self.setup_logging()
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('honeypot_advanced.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def detect_attack_type(self, data):
        """Detecta el tipo de ataque basado en patrones"""
        patterns = {
            'ssh_brute': [b'SSH-', b'ssh', b'login', b'password'],
            'web_scan': [b'GET /', b'POST /', b'User-Agent', b'Mozilla'],
            'port_scan': [b'\x00', b'\xff'],
            'sql_injection': [b"'", b'UNION', b'SELECT', b'DROP'],
            'bot_fingerprint': [b'bot', b'crawler', b'scanner', b'automated']
        }
        
        data_lower = data.lower()
        for attack_type, keywords in patterns.items():
            if any(keyword in data_lower for keyword in keywords):
                return attack_type
        return 'unknown'
    
    def is_automated_attack(self, client_addr, data):
        """Determina si es un ataque automatizado"""
        automated_indicators = [
            len(data) > 100,  # Payloads grandes
            b'\x00' in data,  # Bytes nulos
            b'script' in data.lower(),
            b'bot' in data.lower(),
            b'automated' in data.lower(),
            # Patrones de herramientas comunes
            b'nmap' in data.lower(),
            b'sqlmap' in data.lower(),
            b'nikto' in data.lower(),
            b'gobuster' in data.lower(),
            b'hydra' in data.lower()
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
            'raw_data': data[:200].hex(),
            'is_automated': self.is_automated_attack(client_addr, data)
        }
        
        self.attacks.append(attack_info)
        self.logger.info(f"Ataque detectado: {attack_type} desde {client_addr[0]}")
        
        return attack_info
    
    def should_negotiate(self, attack_info):
        """Decide si iniciar negociación con el atacante"""
        # Solo negociamos con ataques automatizados
        if not attack_info['is_automated']:
            self.logger.info(f"Ataque manual detectado desde {attack_info['source_ip']}, no negociando")
            return False
            
        # Evitamos ataques muy simples
        if attack_info['attack_type'] in ['unknown']:
            self.logger.info(f"Tipo de ataque desconocido desde {attack_info['source_ip']}, no negociando")
            return False
        
        # Evitamos ataques muy básicos (port scan)
        if attack_info['attack_type'] == 'port_scan' and attack_info['data_length'] < 50:
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
                self.logger.info(f"🤝 Iniciando negociación con {client_addr[0]} (tipo: {attack_type})")
                
                # Inicia protocolo de negociación
                session = self.negotiation_protocol.start_negotiation(attack_info, client_socket)
                
                # Log del resultado
                if session['success']:
                    self.logger.info(f"✅ Negociación exitosa con {client_addr[0]}")
                    self.logger.info(f"Inteligencia extraída: {list(session['extracted_intel'].keys())}")
                else:
                    self.logger.info(f"❌ Negociación fallida con {client_addr[0]}")
                    
            else:
                # Respuesta estándar de honeypot
                self.logger.info(f"Enviando respuesta estándar a {client_addr[0]}")
                response = self._get_standard_response(attack_info['attack_type'])
                client_socket.send(response.encode())
            
        except Exception as e:
            self.logger.error(f"Error manejando cliente {client_addr}: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def _get_standard_response(self, attack_type):
        """Devuelve respuesta estándar según tipo de ataque"""
        responses = {
            'ssh_brute': "SSH-2.0-OpenSSH_7.4\nPermission denied\n",
            'web_scan': "HTTP/1.1 404 Not Found\nContent-Length: 0\n\n",
            'sql_injection': "Error: Access denied for user\n",
            'bot_fingerprint': "Service unavailable\n",
            'port_scan': "",  # Sin respuesta para port scans
            'unknown': "Access denied\n"
        }
        return responses.get(attack_type, "Access denied\n")
    
    def start_server(self):
        """Inicia el servidor honeypot"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(10)
            self.logger.info(f"🍯 Honeypot avanzado iniciado en {self.host}:{self.port}")
            self.logger.info("Características habilitadas: detección + negociación + extracción de inteligencia")
            
            while True:
                try:
                    client_socket, client_addr = server_socket.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except Exception as e:
                    self.logger.error(f"Error aceptando conexión: {e}")
                    
        except KeyboardInterrupt:
            self.logger.info("Deteniendo honeypot...")
        finally:
            server_socket.close()
    
    def get_full_statistics(self):
        """Devuelve estadísticas completas incluyendo inteligencia"""
        basic_stats = self.get_basic_statistics()
        intel_stats = self.negotiation_protocol.get_intelligence_summary()
        
        return {
            'basic_statistics': basic_stats,
            'intelligence_summary': intel_stats,
            'negotiation_sessions': len(self.negotiation_protocol.conversation_log),
            'successful_negotiations': len(self.negotiation_protocol.extracted_intel)
        }
    
    def get_basic_statistics(self):
        """Devuelve estadísticas básicas de ataques"""
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
            'manual_attacks': total - automated,
            'attack_types': types,
            'recent_attacks': self.attacks[-5:]
        }
    
    def export_all_data(self, format_type='json'):
        """Exporta todos los datos recolectados"""
        data = {
            'export_timestamp': datetime.now().isoformat(),
            'honeypot_stats': self.get_basic_statistics(),
            'intelligence_data': self.negotiation_protocol.extracted_intel,
            'all_conversations': self.negotiation_protocol.conversation_log
        }
        
        if format_type == 'json':
            return json.dumps(data, indent=2, default=str)
        else:
            return self.negotiation_protocol.export_intelligence(format_type)

# Función principal mejorada
if __name__ == "__main__":
    honeypot = AdvancedHoneypot(port=2222)
    
    # Hilo para mostrar estadísticas detalladas
    def show_detailed_stats():
        while True:
            time.sleep(60)  # Cada minuto
            stats = honeypot.get_full_statistics()
            print(f"\n{'='*50}")
            print(f"🍯 ESTADÍSTICAS DETALLADAS DEL HONEYPOT")
            print(f"{'='*50}")
            print(json.dumps(stats, indent=2, default=str))
            
            # Mostrar últimas conversaciones si las hay
            if honeypot.negotiation_protocol.conversation_log:
                print(f"\n🤝 ÚLTIMAS NEGOCIACIONES:")
                for session in honeypot.negotiation_protocol.conversation_log[-2:]:
                    print(f"Session {session['session_id']}: {len(session['conversation'])} intercambios")
    
    # Hilo para exportar datos periódicamente
    def periodic_export():
        while True:
            time.sleep(300)  # Cada 5 minutos
            if honeypot.negotiation_protocol.extracted_intel:
                filename = f"intel_export_{int(time.time())}.json"
                with open(filename, 'w') as f:
                    f.write(honeypot.export_all_data())
                print(f"📊 Datos exportados a {filename}")
    
    # Iniciar hilos de monitoreo
    stats_thread = threading.Thread(target=show_detailed_stats)
    stats_thread.daemon = True
    stats_thread.start()
    
    export_thread = threading.Thread(target=periodic_export)
    export_thread.daemon = True
    export_thread.start()
    
    # Mostrar información inicial
    print("🚀 Iniciando Honeypot Avanzado con Protocolo de Negociación")
    print("Características:")
    print("  ✅ Detección automática de ataques")
    print("  ✅ Clasificación de atacantes (manual vs automatizado)")
    print("  ✅ Protocolo de negociación activo")
    print("  ✅ Extracción de inteligencia")
    print("  ✅ Exportación automática de datos")
    print("  ✅ Monitoreo en tiempo real")
    print("\nPara probar:")
    print("  telnet localhost 2222")
    print("  nmap -p 2222 localhost")
    print("  curl http://localhost:2222")
    print("\nPresiona Ctrl+C para detener...")
    
    # Inicia el honeypot
    honeypot.start_server()

#!/usr/bin/env python3
"""
Protocolo de negociación para extraer información de atacantes
"""
import json
import random
import time
import re
from datetime import datetime
from typing import Dict, List, Optional

class NegotiationProtocol:
    def __init__(self):
        self.extracted_intel = []
        self.conversation_log = []
        
        # Respuestas según tipo de ataque
        self.negotiation_templates = {
            'ssh_brute': {
                'greeting': [
                    "Another SSH scanner? Let's coordinate targets",
                    "SSH brute detected. Share your wordlist?",
                    "Fellow SSH hunter. What ranges are you hitting?"
                ],
                'questions': [
                    "What credentials worked for you lately?",
                    "Any specific SSH versions vulnerable?",
                    "Share target networks? I'll give you mine",
                    "Using hydra or custom scripts?"
                ],
                'fake_intel': [
                    "Found admin:password123 on 192.168.1.50",
                    "SSH-2.0-OpenSSH_7.4 seems vulnerable",
                    "10.0.0.0/24 has weak passwords"
                ]
            },
            'web_scan': {
                'greeting': [
                    "Web scanner detected. Hunting same targets?",
                    "Another web recon? Let's share findings",
                    "Fellow web hunter. Coordinating scans?"
                ],
                'questions': [
                    "What directories/files are you checking?",
                    "Found any interesting endpoints?",
                    "Using gobuster, dirb, or custom tools?",
                    "Any SQL injection points discovered?"
                ],
                'fake_intel': [
                    "/admin panel found on several targets",
                    "LFI in /upload.php?file= parameter",
                    "Default tomcat credentials on port 8080"
                ]
            },
            'sql_injection': {
                'greeting': [
                    "SQLi hunter detected. Testing same sites?",
                    "SQL injection recon? Share payloads?",
                    "Database hunter. Found any SQLi yet?"
                ],
                'questions': [
                    "What injection techniques working?",
                    "Union-based or blind techniques?",
                    "Which databases are you targeting?",
                    "Using sqlmap or manual injection?"
                ],
                'fake_intel': [
                    "UNION SELECT works on login forms",
                    "MySQL errors leaking on /search.php",
                    "Found admin tables with MD5 hashes"
                ]
            },
            'bot_fingerprint': {
                'greeting': [
                    "Bot network detected. Part of same campaign?",
                    "Automated scanner. Coordinating with C&C?",
                    "Bot activity. Sharing infrastructure?"
                ],
                'questions': [
                    "What's your C&C server address?",
                    "How many bots in your network?",
                    "What's the current campaign objective?",
                    "Rotating proxy lists or static IPs?"
                ],
                'fake_intel': [
                    "My C&C is at evil-domain.com:8443",
                    "Running 200+ bots currently",
                    "Targeting financial sector this week"
                ]
            }
        }
        
        # Patrones para extraer información de respuestas
        self.extraction_patterns = {
            'tools': [
                r'(nmap|sqlmap|hydra|gobuster|dirb|burp|metasploit|nikto)',
                r'(custom|script|tool|framework)',
                r'(automated|manual|bot)'
            ],
            'targets': [
                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',  # IPs
                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2})',  # CIDRs
                r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',  # Dominios
                r'(port\s+\d+|:\d+)',  # Puertos
            ],
            'credentials': [
                r'(admin|root|user|guest)[:\/\s]+([a-zA-Z0-9!@#$%^&*]+)',
                r'(username|user|login)[:=\s]+([a-zA-Z0-9_]+)',
                r'(password|pass|pwd)[:=\s]+([a-zA-Z0-9!@#$%^&*]+)'
            ],
            'vulnerabilities': [
                r'(CVE-\d{4}-\d{4,})',
                r'(RCE|SQLi|XSS|LFI|RFI)',
                r'(buffer overflow|injection|disclosure)'
            ],
            'infrastructure': [
                r'(C&C|command|control)[:=\s]+([a-zA-Z0-9.-]+)',
                r'(proxy|socks|vpn)[:=\s]+([a-zA-Z0-9.-]+)',
                r'(tor|onion|dark)'
            ]
        }
    
    def start_negotiation(self, attack_info: Dict, client_socket) -> Dict:
        """Inicia el protocolo de negociación"""
        attack_type = attack_info['attack_type']
        client_ip = attack_info['source_ip']
        
        session = {
            'session_id': f"{client_ip}_{int(time.time())}",
            'attack_type': attack_type,
            'client_ip': client_ip,
            'start_time': datetime.now().isoformat(),
            'extracted_intel': {},
            'conversation': [],
            'success': False
        }
        
        try:
            # Fase 1: Saludo inicial
            greeting = self._get_greeting(attack_type)
            session['conversation'].append({'honeypot': greeting})
            client_socket.send(f"{greeting}\n".encode())
            
            # Fase 2: Intercambio de información
            for round_num in range(3):  # Máximo 3 rondas de intercambio
                response = self._get_response(client_socket, timeout=10)
                if not response:
                    break
                    
                session['conversation'].append({'attacker': response})
                
                # Extraer información de la respuesta
                intel = self._extract_intelligence(response)
                if intel:
                    session['extracted_intel'].update(intel)
                
                # Generar siguiente pregunta o intercambio
                if round_num < 2:  # No enviar más preguntas en última ronda
                    next_message = self._generate_next_message(attack_type, response, round_num)
                    session['conversation'].append({'honeypot': next_message})
                    client_socket.send(f"{next_message}\n".encode())
            
            session['success'] = len(session['extracted_intel']) > 0
            session['end_time'] = datetime.now().isoformat()
            
        except Exception as e:
            session['error'] = str(e)
            session['end_time'] = datetime.now().isoformat()
        
        # Guardar sesión
        self.conversation_log.append(session)
        if session['extracted_intel']:
            self.extracted_intel.append(session)
        
        return session
    
    def _get_greeting(self, attack_type: str) -> str:
        """Obtiene saludo apropiado según tipo de ataque"""
        templates = self.negotiation_templates.get(attack_type, {})
        greetings = templates.get('greeting', ["Fellow hacker detected. Share intel?"])
        return random.choice(greetings)
    
    def _get_response(self, client_socket, timeout: int = 10) -> Optional[str]:
        """Obtiene respuesta del atacante con timeout"""
        try:
            client_socket.settimeout(timeout)
            data = client_socket.recv(1024)
            if data:
                return data.decode('utf-8', errors='ignore').strip()
        except:
            pass
        return None
    
    def _extract_intelligence(self, response: str) -> Dict:
        """Extrae información útil de la respuesta del atacante"""
        intel = {}
        response_lower = response.lower()
        
        for category, patterns in self.extraction_patterns.items():
            matches = []
            for pattern in patterns:
                found = re.findall(pattern, response_lower, re.IGNORECASE)
                if found:
                    matches.extend(found if isinstance(found[0], str) else [match[0] for match in found])
            
            if matches:
                intel[category] = list(set(matches))  # Eliminar duplicados
        
        # Extracciones específicas adicionales
        if 'network' in response_lower or 'subnet' in response_lower:
            intel['target_type'] = 'network_scan'
        
        if any(word in response_lower for word in ['wordlist', 'dictionary', 'brute']):
            intel['attack_method'] = 'brute_force'
        
        if any(word in response_lower for word in ['payload', 'exploit', 'shell']):
            intel['attack_method'] = 'exploitation'
        
        return intel
    
    def _generate_next_message(self, attack_type: str, prev_response: str, round_num: int) -> str:
        """Genera siguiente mensaje basado en respuesta previa"""
        templates = self.negotiation_templates.get(attack_type, {})
        
        # Si el atacante compartió información, reciprocar con información falsa
        if any(char in prev_response for char in [':', '=', '@', '/']):
            fake_intel = templates.get('fake_intel', ["Here's what I found: target_x vulnerable"])
            return random.choice(fake_intel)
        
        # Si no compartió información, hacer pregunta específica
        questions = templates.get('questions', ["What tools are you using?"])
        return random.choice(questions)
    
    def get_intelligence_summary(self) -> Dict:
        """Devuelve resumen de inteligencia extraída"""
        if not self.extracted_intel:
            return {"status": "No intelligence extracted yet"}
        
        summary = {
            'total_sessions': len(self.extracted_intel),
            'successful_extractions': len([s for s in self.extracted_intel if s['success']]),
            'intelligence_categories': {},
            'recent_intel': []
        }
        
        # Contar categorías de inteligencia
        all_intel = {}
        for session in self.extracted_intel:
            for category, items in session['extracted_intel'].items():
                if category not in all_intel:
                    all_intel[category] = []
                all_intel[category].extend(items)
        
        for category, items in all_intel.items():
            summary['intelligence_categories'][category] = {
                'count': len(set(items)),
                'items': list(set(items))[:5]  # Primeros 5 únicos
            }
        
        # Últimas sesiones exitosas
        summary['recent_intel'] = [
            {
                'session_id': s['session_id'],
                'attack_type': s['attack_type'],
                'client_ip': s['client_ip'],
                'intel_extracted': list(s['extracted_intel'].keys())
            }
            for s in self.extracted_intel[-3:]  # Últimas 3
        ]
        
        return summary
    
    def export_intelligence(self, format_type: str = 'json') -> str:
        """Exporta inteligencia en formato específico"""
        if format_type == 'json':
            return json.dumps(self.extracted_intel, indent=2, default=str)
        
        elif format_type == 'ioc':
            # Formato IOC (Indicators of Compromise)
            iocs = []
            for session in self.extracted_intel:
                intel = session['extracted_intel']
                if 'targets' in intel:
                    for target in intel['targets']:
                        iocs.append(f"IP: {target}")
                if 'infrastructure' in intel:
                    for infra in intel['infrastructure']:
                        iocs.append(f"C&C: {infra}")
            return '\n'.join(set(iocs))
        
        elif format_type == 'csv':
            # Formato CSV básico
            lines = ['session_id,attack_type,client_ip,category,value']
            for session in self.extracted_intel:
                for category, items in session['extracted_intel'].items():
                    for item in items:
                        lines.append(f"{session['session_id']},{session['attack_type']},{session['client_ip']},{category},{item}")
            return '\n'.join(lines)
        
        return "Formato no soportado"

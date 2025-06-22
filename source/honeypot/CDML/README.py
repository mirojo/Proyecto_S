# CDML - Cyber Diplomacy Markup Language

**Versión 1.0**

Lenguaje de marcado XML estructurado para comunicación entre agentes de IA autónomos en contextos de ciberseguridad y diplomacia digital.

## 🎯 Propósito

CDML permite que agentes de IA autónomos (honeypots, scanners, sistemas de análisis) se comuniquen, negocien e intercambien inteligencia de amenazas de forma estructurada y segura.

## 🚀 Características Principales

- **Comunicación Estructurada**: Mensajes XML estandarizados con validación
- **Negociación Automática**: Protocolos para intercambio de inteligencia
- **Seguridad Integrada**: Firmas digitales, hashing y verificación de integridad
- **Tipos de Mensaje**: Discovery, Proposal, Response, Agreement, Termination
- **Inteligencia de Amenazas**: Soporte nativo para IOCs, TTPs, vulnerabilidades
- **Sistema de Confianza**: Manejo adaptativo de niveles de confianza entre agentes

## 📦 Instalación

```python
# Importar desde el proyecto principal
from cdml import CDMLMessage, CDMLNegotiationEngine, AgentType

# O importar componentes específicos
from cdml.core.message import CDMLMessage
from cdml.core.engine import CDMLNegotiationEngine
from cdml.core.validator import CDMLValidator
```

## 🎮 Uso Rápido

### Crear Motor de Negociación
```python
from cdml import CDMLNegotiationEngine, AgentType, ThreatIntelligence, IOC

# Crear motor para un honeypot
engine = CDMLNegotiationEngine("honeypot-alpha-001", AgentType.HONEYPOT)

# Iniciar descubrimiento con otro agente
discovery_msg = engine.initiate_discovery("scanner-beta-002")
print(discovery_msg.to_xml())
```

### Intercambio de Inteligencia
```python
# Crear inteligencia de amenazas
threat_intel = ThreatIntelligence()
threat_intel.indicators = [
    IOC(type="ip", value="192.168.1.100", confidence=0.9),
    IOC(type="domain", value="malicious-site.com", confidence=0.8)
]

# Proponer intercambio
proposal = engine.propose_intelligence_exchange(
    target_agent="scanner-beta-002",
    threat_intel=threat_intel,
    requested_info="attack-tools"
)
```

### Procesamiento de Mensajes
```python
# Procesar mensaje entrante
incoming_xml = """<cdml-message version="1.0">...</cdml-message>"""
response = engine.process_incoming_message(incoming_xml)

if response:
    print("Respuesta generada:", response.to_xml())
```

## 📋 Tipos de Mensaje

### 1. Discovery - Descubrimiento
```python
discovery = engine.initiate_discovery(
    target_agent="unknown-agent-001",
    capabilities={
        "threat-detection": 0.9,
        "intelligence-analysis": 0.8
    }
)
```

### 2. Proposal - Propuesta
```python
proposal = engine.propose_intelligence_exchange(
    target_agent="partner-agent",
    threat_intel=my_intelligence,
    requested_info="vulnerability-data"
)
```

### 3. Response - Respuesta
```python
# Las respuestas se generan automáticamente por el motor
# basadas en la evaluación de propuestas entrantes
```

### 4. Agreement - Acuerdo
```python
# Los acuerdos se crean automáticamente cuando
# las negociaciones son exitosas
```

## 🔍 Validación de Mensajes

```python
from cdml import CDMLValidator

validator = CDMLValidator()

# Validar mensaje
validation_result = validator.validate_message(message)

if validation_result["is_valid"]:
    print("✅ Mensaje válido")
else:
    print("❌ Errores:", validation_result["errors"])
    print("⚠️ Advertencias:", validation_result["warnings"])

# Obtener resumen de validación
summary = validator.get_validation_summary(validation_result)
print(summary)
```

## 📊 Inteligencia de Amenazas

### Tipos de Datos Soportados

```python
from cdml import IOC, AttackPattern, Vulnerability, ToolInformation

# Indicadores de Compromiso
ioc = IOC(type="ip", value="10.0.0.1", confidence=0.9)

# Patrones de Ataque (MITRE ATT&CK)
pattern = AttackPattern(mitre_id="T1071", name="Application Layer Protocol")

# Vulnerabilidades
vulnerability = Vulnerability(cve="CVE-2024-1234", severity="high")

# Información de Herramientas
tool = ToolInformation(name="nmap", version="7.94", usage="scanning")
```

### Extraer Inteligencia de Mensajes
```python
# Extraer inteligencia de un mensaje
threat_intel = message.get_threat_intelligence()

if threat_intel:
    print(f"IOCs encontrados: {len(threat_intel.indicators)}")
    print(f"Herramientas: {len(threat_intel.tools)}")
    print(f"Confianza: {threat_intel.confidence}")
```

## 🔒 Seguridad

### Verificación de Integridad
```python
# Verificar integridad del mensaje
if message.verify_integrity():
    print("✅ Integridad verificada")
else:
    print("❌ Mensaje comprometido")
```

### Información de Seguridad
```python
if message.security:
    print(f"Firmado: {message.security.is_signed()}")
    print(f"Cifrado: {message.security.is_encrypted()}")
    print(f"Integridad: {message.security.has_integrity_protection()}")
```

## 📈 Monitoreo y Estadísticas

### Estadísticas del Motor
```python
stats = engine.get_statistics()
print(f"Sesiones activas: {stats['active_sessions']}")
print(f"Negociaciones exitosas: {stats['successful_negotiations']}")
print(f"Inteligencia extraída: {stats['intelligence_extracted']}")
```

### Sesiones Activas
```python
# Obtener resumen de todas las sesiones
sessions = engine.get_all_sessions_summary()
for session in sessions:
    print(f"Sesión {session['session_id']}: {session['status']}")
```

### Niveles de Confianza
```python
# Consultar nivel de confianza
trust = engine.get_trust_level("partner-agent-001")
print(f"Confianza: {trust:.2f}")

# Establecer nivel de confianza
engine.set_trust_level("partner-agent-001", 0.8)
```

## 🧪 Ejemplo

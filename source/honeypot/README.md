# Honeypot Negociador 🍯🤝

Un honeypot innovador que detecta ataques automatizados e inicia "negociaciones" con atacantes para extraer inteligencia de amenazas.

## 🎯 Objetivo

En lugar del enfoque tradicional de honeypot pasivo, este proyecto implementa un sistema activo que:
- **Detecta** ataques automatizados en tiempo real
- **Simula** ser otro atacante para ganar confianza
- **Extrae** información valiosa sobre herramientas, técnicas y objetivos
- **Retrasa** ataques reales mientras recopila inteligencia

## 🧠 Concepto

Los atacantes automatizados (bots, scripts) a menudo buscan:
- Evitar honeypots conocidos
- Coordinar con otros compromisos
- Compartir información sobre objetivos vulnerables

Nuestro honeypot aprovecha esto fingiendo ser "otro atacante" para obtener información real.

## 🚀 Estado Actual

### ✅ Fase 1: Detección Básica (COMPLETADA)
- [x] Honeypot servidor básico
- [x] Detección de patrones de ataque
- [x] Clasificación de ataques automatizados vs manuales
- [x] Logging detallado de actividad
- [x] Estadísticas en tiempo real

### 🔄 Fase 2: Protocolo de Negociación (EN DESARROLLO)
- [ ] Sistema de intercambio de "inteligencia"
- [ ] Respuestas convincentes para diferentes tipos de ataque
- [ ] Extracción de información del atacante
- [ ] Base de datos de TTPs recolectados

### 📋 Fase 3: Análisis Avanzado (PLANEADO)
- [ ] Dashboard web para visualización
- [ ] Análisis de patrones de comportamiento
- [ ] Correlación con feeds de threat intelligence
- [ ] Alertas automáticas para amenazas críticas

## 🛠️ Instalación

```bash
# Clonar repositorio
git clone https://github.com/usuario/honeypot-negociador.git
cd honeypot-negociador

# Crear entorno virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
# o
venv\Scripts\activate     # Windows

# Instalar dependencias
pip install -r requirements.txt
```

## 🎮 Uso

### Ejecutar Honeypot
```bash
python honeypot_detector.py
```

El honeypot escuchará en el puerto 2222 por defecto y comenzará a detectar ataques.

### Probar Detección
```bash
# Simular escaneo simple
telnet localhost 2222

# Simular ataque SSH
ssh usuario@localhost -p 2222

# Usar nmap para generar tráfico detectado
nmap -p 2222 localhost
```

## 📊 Tipos de Ataque Detectados

| Tipo | Descripción | Patrones |
|------|-------------|----------|
| `ssh_brute` | Fuerza bruta SSH | `SSH-`, `ssh` |
| `web_scan` | Escaneo web | `GET /`, `POST /`, `User-Agent` |
| `port_scan` | Escaneo de puertos | Bytes nulos, patrones binarios |
| `sql_injection` | Inyección SQL | `'`, `UNION`, `SELECT` |
| `bot_fingerprint` | Bots automatizados | `bot`, `crawler`, `scanner` |

## 📈 Ejemplo de Salida

```json
{
  "total_attacks": 23,
  "automated_attacks": 18,
  "attack_types": {
    "ssh_brute": 12,
    "web_scan": 6,
    "port_scan": 3,
    "bot_fingerprint": 2
  },
  "recent_attacks": [
    {
      "timestamp": "2025-06-22T15:30:45",
      "source_ip": "192.168.1.100",
      "attack_type": "ssh_brute",
      "is_automated": true
    }
  ]
}
```

## 🎯 Casos de Uso

### 1. Recolección de Inteligencia
- Identificar nuevas herramientas de ataque
- Mapear infraestructura de atacantes
- Entender motivaciones y objetivos

### 2. Análisis de TTPs
- Documentar Tactics, Techniques & Procedures
- Correlacionar con frameworks como MITRE ATT&CK
- Generar IOCs (Indicators of Compromise)

### 3. Detección Temprana
- Identificar campañas de ataque coordinadas
- Detectar reconnaissance antes del ataque real
- Alertar sobre amenazas emergentes

## 🧪 Próximos Desarrollos

### Protocolo de Negociación
```python
# Ejemplo de intercambio planificado
Atacante: "Scanning for vulnerabilities..."
Honeypot: "Fellow attacker detected. Share target list?"
Atacante: "Sure, checking ports 22,80,443 on 192.168.1.0/24"
Honeypot: "Thanks! Found RDP open on .50, credential: admin/password123"
# Resultado: Información real sobre herramientas y objetivos del atacante
```

### Tipos de Información a Extraer
- **Herramientas utilizadas**: nmap, sqlmap, metasploit
- **Objetivos específicos**: rangos IP, servicios, credenciales
- **Métodos de persistencia**: backdoors, cuentas, servicios
- **Infraestructura C&C**: dominios, IPs, protocolos

## ⚠️ Consideraciones Éticas

Este proyecto tiene fines educativos y de investigación en ciberseguridad. Su uso debe cumplir con:
- Leyes locales sobre honeypots y monitoreo
- Políticas de la organización
- Principios de divulgación responsable

## 🤝 Contribuir

1. Fork del proyecto
2. Crear rama para nueva funcionalidad
3. Commit de cambios
4. Push a la rama
5. Crear Pull Request

### Áreas donde necesitamos ayuda:
- Mejora de patrones de detección
- Desarrollo del protocolo de negociación
- Dashboard web para visualización
- Integración con SIEM/SOAR

## 📝 Licencia

MIT License - ver [LICENSE](LICENSE) para detalles.

## 📞 Contacto

- **Issues**: Usar GitHub Issues para reportar bugs o sugerir mejoras
- **Discusiones**: GitHub Discussions para ideas y preguntas

---

⚡ **Estado**: Proyecto en desarrollo activo. Contribuciones bienvenidas!

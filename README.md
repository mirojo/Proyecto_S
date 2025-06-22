# Proyecto S - Honeypot Negociador 🍯🤝

**Definición de entornos de negociación para sistemas automatizados**

Un honeypot innovador que implementa protocolos de "diplomacia digital" mediante la simulación de negociaciones entre atacantes automatizados para extraer inteligencia de amenazas.

## 🎯 Concepto Principal

En lugar del tradicional modelo de defensa versus ataque, Proyecto S explora mecanismos de **diplomacia digital**, donde el honeypot negocia, pacta y simula colaborar con atacantes automatizados para:

- **Minimizar conflictos** retrasando ataques reales
- **Fortalecer la seguridad** extrayendo inteligencia valiosa  
- **Crear ecosistemas colaborativos** de recolección de amenazas

## 🚀 Implementación Actual

### ✅ Fase 1: Protocolo de Detección (COMPLETADA)
- [x] Honeypot servidor con detección automática
- [x] Clasificación de ataques (SSH brute force, web scan, SQL injection, etc.)
- [x] Identificación de ataques automatizados vs manuales
- [x] Sistema de logging y estadísticas en tiempo real

### ✅ Fase 2: Protocolo de Negociación (COMPLETADA)
- [x] Sistema de intercambio de "inteligencia" con atacantes
- [x] Respuestas convincentes específicas por tipo de ataque
- [x] Extracción automática de información del atacante
- [x] Base de datos de TTPs (Tactics, Techniques & Procedures)

### 🔄 Fase 3: Análisis Avanzado (EN DESARROLLO)
- [ ] Dashboard web para visualización de inteligencia
- [ ] Correlación con feeds de threat intelligence externos
- [ ] Integración con SIEM/SOAR
- [ ] Alertas automáticas para amenazas críticas

## 🛠️ Instalación

```bash
# Clonar repositorio
git clone https://github.com/mirojo/Proyecto_S.git
cd Proyecto_S

# Crear entorno virtual
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate

# Instalar dependencias
pip install -r requirements.txt
```

## 🎮 Uso

### Ejecutar Honeypot Básico (Solo Detección)
```bash
python honeypot_detector.py
```

### Ejecutar Honeypot Avanzado (Con Negociación)
```bash
python honeypot_advanced.py
```

El honeypot escuchará en el puerto 2222 por defecto y comenzará a detectar y negociar con atacantes automatizados.

### Probar el Sistema
```bash
# Simular escaneo SSH (activará negociación)
nmap -p 2222 localhost

# Simular ataque web (activará negociación)  
curl -H "User-Agent: sqlmap/1.0" http://localhost:2222

# Ataque manual simple (NO activará negociación)
telnet localhost 2222
```

## 📊 Tipos de Negociación Implementados

| Tipo de Ataque | Estrategia de Negociación | Información Extraída |
|----------------|---------------------------|---------------------|
| `ssh_brute` | "Fellow SSH hunter. Share targets?" | Herramientas, rangos IP, credenciales |
| `web_scan` | "Another web recon? Let's coordinate" | Directorios, endpoints, payloads |
| `sql_injection` | "SQLi hunter detected. Share techniques?" | Técnicas, bases de datos, herramientas |
| `bot_fingerprint` | "Bot network? Coordinating with C&C?" | Infraestructura, objetivos, campañas |

## 🧠 Funcionamiento del Protocolo

### Ejemplo de Negociación Exitosa:
```
🤖 Atacante: [Escaneo SSH detectado con herramientas automatizadas]
🍯 Honeypot: "Another SSH scanner? Let's coordinate targets"
🤖 Atacante: "Using hydra on 192.168.1.0/24, trying common passwords"  
🍯 Honeypot: "Found admin:password123 on 192.168.1.50"
🤖 Atacante: "Thanks! I'm hitting ports 22,80,443 with custom wordlist"

📈 Inteligencia Extraída:
- Herramienta: hydra
- Objetivo: 192.168.1.0/24  
- Método: wordlist personalizada
- Puertos: 22,80,443
```

## 📈 Salida de Ejemplo

```json
{
  "intelligence_summary": {
    "total_sessions": 15,
    "successful_extractions": 12,
    "intelligence_categories": {
      "tools": {
        "count": 8,
        "items": ["hydra", "nmap", "sqlmap", "gobuster", "nikto"]
      },
      "targets": {
        "count": 23,
        "items": ["192.168.1.0/24", "10.0.0.50", "example.com"]
      },
      "credentials": {
        "count": 5,
        "items": ["admin:123456", "root:password", "user:test"]
      }
    }
  }
}
```

## 🎯 Casos de Uso

### 1. **Threat Intelligence Collection**
- Identificar nuevas herramientas y técnicas de ataque
- Mapear infraestructura de atacantes (C&C, proxies)
- Documentar campaigns coordinadas

### 2. **Early Warning System**  
- Detectar reconnaissance antes del ataque real
- Identificar objetivos específicos de campañas
- Alertar sobre amenazas emergentes

### 3. **Security Research**
- Estudiar comportamiento de atacantes automatizados
- Analizar evolución de técnicas de ataque
- Generar IOCs (Indicators of Compromise)

## 📁 Estructura del Proyecto

```
Proyecto_S/source/honeypot/
├── README.md
├── requirements.txt
├── honeypot_detector.py      # Versión básica (solo detección)
├── negotiation_protocol.py   # Protocolo de negociación
├── honeypot_advanced.py     # Versión completa integrada
├── docs/                    # Documentación adicional
├── logs/                    # Logs del sistema
└── exports/                 # Datos exportados
```

## 🔒 Protocolos de Seguridad

- **Identificación segura**: Detección de patrones automatizados sin falsos positivos
- **Autenticación**: Verificación de legitimidad de atacantes antes de negociar  
- **Comunicación cifrada**: Intercambios seguros durante la negociación
- **Aislamiento**: Honeypot completamente aislado de sistemas productivos

## 📋 Próximos Desarrollos

### Dashboard de Inteligencia
- Visualización en tiempo real de amenazas
- Correlación geográfica de ataques
- Timeline de campañas detectadas

### Integración MITRE ATT&CK
- Mapeo automático de TTPs a framework
- Generación de reportes técnicos
- Correlación con threat feeds públicos

### Machine Learning
- Detección automática de nuevos patrones
- Predicción de comportamiento de atacantes
- Clasificación avanzada de amenazas

## ⚠️ Consideraciones Éticas y Legales

Este proyecto tiene fines **educativos y de investigación** en ciberseguridad. Su uso debe cumplir con:

- ✅ Leyes locales sobre honeypots y monitoreo de red
- ✅ Políticas organizacionales de seguridad  
- ✅ Principios de divulgación responsable de vulnerabilidades
- ✅ Normativas de privacidad y protección de datos

## 🤝 Contribuir

Bienvenidas contribuciones para:

1. **Mejorar protocolos de negociación** y detección de fraude
2. **Extender simulaciones** a escenarios más complejos  
3. **Integrar machine learning** para análisis de comportamiento
4. **Desarrollar dashboard web** para visualización
5. **Crear integraciones** con SIEM/SOAR

### Proceso de Contribución:
1. Fork del proyecto
2. Crear rama para nueva funcionalidad (`git checkout -b feature/nueva-funcionalidad`)
3. Commit de cambios (`git commit -am 'Añadir nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Crear Pull Request

Por favor, abre un **issue** o **pull request** para discutir cambios.

## 📊 Métricas del Proyecto

![GitHub stars](https://img.shields.io/github/stars/mirojo/Proyecto_S)
![GitHub forks](https://img.shields.io/github/forks/mirojo/Proyecto_S)
![GitHub issues](https://img.shields.io/github/issues/mirojo/Proyecto_S)
![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## 📝 Licencia

Este proyecto está bajo la **Licencia MIT** - ver el archivo [LICENSE](LICENSE) para detalles.

## 📞 Contacto

- **Autora**: María Rojo (@mirojo)
- **Email**: Via GitHub Issues
- - **LinkedIn**: [María Rojo](https://www.linkedin.com/in/mar%C3%ADa-rojo/)

---

⚡ **Estado**: Proyecto en desarrollo activo. ¡Contribuciones bienvenidas!

*"En lugar de construir muros más altos, construyamos puentes más inteligentes"* - Filosofía del Proyecto S

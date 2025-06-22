"""
CDML - Cyber Diplomacy Markup Language
Version 1.0

A structured XML markup language for communication between autonomous AI agents
in cybersecurity and digital diplomacy contexts.

Author: María Rojo
GitHub: https://github.com/mirojo/Proyecto_S
"""

from .core.message import CDMLMessage
from .core.validator import CDMLValidator  
from .core.engine import CDMLNegotiationEngine
from .core.types import (
    MessageType, AgentType, Priority, DecisionType,
    IOC, AttackPattern, Vulnerability, ToolInformation, ThreatIntelligence,
    CDMLHeader, CDMLSecurity
)

__version__ = "1.0.0"
__author__ = "María Rojo"
__email__ = "https://github.com/mirojo"
__license__ = "MIT"

__all__ = [
    # Main classes
    'CDMLMessage', 
    'CDMLValidator', 
    'CDMLNegotiationEngine',
    
    # Enums
    'MessageType', 
    'AgentType', 
    'Priority', 
    'DecisionType',
    
    # Data structures
    'IOC', 
    'AttackPattern', 
    'Vulnerability', 
    'ToolInformation', 
    'ThreatIntelligence',
    'CDMLHeader',
    'CDMLSecurity'
]

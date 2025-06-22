"""
CDML Core Module
Core components for CDML message processing
"""

from .types import (
    MessageType, AgentType, Priority, DecisionType,
    IOC, AttackPattern, Vulnerability, ToolInformation, ThreatIntelligence,
    CDMLHeader, CDMLSecurity
)
from .message import CDMLMessage
from .validator import CDMLValidator
from .engine import CDMLNegotiationEngine

__all__ = [
    # Types
    'MessageType', 'AgentType', 'Priority', 'DecisionType',
    'IOC', 'AttackPattern', 'Vulnerability', 'ToolInformation', 'ThreatIntelligence',
    'CDMLHeader', 'CDMLSecurity',
    
    # Core classes
    'CDMLMessage', 'CDMLValidator', 'CDMLNegotiationEngine'
]

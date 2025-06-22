#!/usr/bin/env python3
"""
CDML Core Types
Data structures and enums for CDML messages
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

class MessageType(Enum):
    """Types of CDML messages"""
    DISCOVERY = "discovery"
    PROPOSAL = "proposal"
    RESPONSE = "response"
    AGREEMENT = "agreement"
    TERMINATION = "termination"

class AgentType(Enum):
    """Types of AI agents"""
    HONEYPOT = "honeypot"
    SCANNER = "scanner"
    BOT = "bot"
    ANALYZER = "analyzer"
    UNKNOWN = "unknown"

class Priority(Enum):
    """Message priority levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class DecisionType(Enum):
    """Response decision types"""
    ACCEPT = "accept"
    REJECT = "reject"
    COUNTER = "counter"
    REQUEST_CLARIFICATION = "request-clarification"

@dataclass
class IOC:
    """Indicator of Compromise"""
    type: str  # ip, domain, url, hash, file-path
    value: str
    confidence: float = 0.0
    source: Optional[str] = None
    
    def __post_init__(self):
        """Validate IOC data"""
        if not self.type or not self.value:
            raise ValueError("IOC type and value are required")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Confidence must be between 0.0 and 1.0")

@dataclass
class AttackPattern:
    """MITRE ATT&CK Pattern"""
    mitre_id: str
    name: str
    confidence: float = 0.0
    
    def __post_init__(self):
        """Validate attack pattern data"""
        if not self.mitre_id or not self.name:
            raise ValueError("MITRE ID and name are required")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Confidence must be between 0.0 and 1.0")

@dataclass
class Vulnerability:
    """Vulnerability Information"""
    cve: str
    severity: str  # low, medium, high, critical
    exploitability: float = 0.0
    description: Optional[str] = None
    
    def __post_init__(self):
        """Validate vulnerability data"""
        valid_severities = ["low", "medium", "high", "critical"]
        if self.severity not in valid_severities:
            raise ValueError(f"Severity must be one of: {valid_severities}")
        if not 0.0 <= self.exploitability <= 1.0:
            raise ValueError("Exploitability must be between 0.0 and 1.0")

@dataclass
class ToolInformation:
    """Attack Tool Information"""
    name: str
    version: Optional[str] = None
    usage: Optional[str] = None
    effectiveness: float = 0.0
    
    def __post_init__(self):
        """Validate tool information"""
        if not self.name:
            raise ValueError("Tool name is required")
        if not 0.0 <= self.effectiveness <= 1.0:
            raise ValueError("Effectiveness must be between 0.0 and 1.0")

@dataclass
class ThreatIntelligence:
    """Complete Threat Intelligence Package"""
    indicators: List[IOC] = field(default_factory=list)
    attack_patterns: List[AttackPattern] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    tools: List[ToolInformation] = field(default_factory=list)
    confidence: float = 0.0
    source_reliability: str = "F"  # A-F scale (A=completely reliable, F=unreliable)
    
    def __post_init__(self):
        """Validate threat intelligence data"""
        valid_reliability = ["A", "B", "C", "D", "E", "F"]
        if self.source_reliability not in valid_reliability:
            raise ValueError(f"Source reliability must be one of: {valid_reliability}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Confidence must be between 0.0 and 1.0")
    
    def is_empty(self) -> bool:
        """Check if threat intelligence contains any data"""
        return (len(self.indicators) == 0 and 
                len(self.attack_patterns) == 0 and
                len(self.vulnerabilities) == 0 and 
                len(self.tools) == 0)
    
    def get_summary(self) -> str:
        """Get a summary of the threat intelligence"""
        return (f"ThreatIntel(IOCs: {len(self.indicators)}, "
                f"Patterns: {len(self.attack_patterns)}, "
                f"Vulns: {len(self.vulnerabilities)}, "
                f"Tools: {len(self.tools)}, "
                f"Confidence: {self.confidence:.2f})")

@dataclass
class CDMLHeader:
    """CDML Message Header"""
    sender_id: str
    receiver_id: str
    session_id: str
    timestamp: str
    message_type: MessageType
    sender_type: AgentType = AgentType.UNKNOWN
    trust_level: float = 0.0
    priority: Priority = Priority.MEDIUM
    protocol_version: str = "1.0"
    
    def __post_init__(self):
        """Validate header data"""
        if not all([self.sender_id, self.receiver_id, self.session_id, self.timestamp]):
            raise ValueError("All header fields are required")
        if not 0.0 <= self.trust_level <= 1.0:
            raise ValueError("Trust level must be between 0.0 and 1.0")

@dataclass
class CDMLSecurity:
    """CDML Security Information"""
    encryption_algorithm: Optional[str] = None
    signature_algorithm: Optional[str] = None
    signature: Optional[str] = None
    certificate: Optional[str] = None
    message_hash: Optional[str] = None
    nonce: Optional[str] = None
    
    def is_signed(self) -> bool:
        """Check if message is digitally signed"""
        return self.signature is not None
    
    def is_encrypted(self) -> bool:
        """Check if message is encrypted"""
        return self.encryption_algorithm is not None
    
    def has_integrity_protection(self) -> bool:
        """Check if message has integrity protection"""
        return self.message_hash is not None

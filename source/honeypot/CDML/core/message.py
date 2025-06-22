#!/usr/bin/env python3
"""
CDML Message Implementation
Core message creation, parsing and manipulation
"""

import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom
from datetime import datetime, timezone
import uuid
import hashlib
from typing import Dict, List, Optional, Union, Any

from .types import (
    MessageType, AgentType, Priority, DecisionType,
    IOC, AttackPattern, Vulnerability, ToolInformation, ThreatIntelligence,
    CDMLHeader, CDMLSecurity
)

class CDMLMessage:
    """Main CDML Message Class"""
    
    def __init__(self):
        self.header: Optional[CDMLHeader] = None
        self.body: Dict[str, Any] = {}
        self.security: Optional[CDMLSecurity] = None
        self.namespace = "http://proyectos.cdml.org/schema/v1"
    
    def create_discovery_message(self, sender_id: str, receiver_id: str, 
                                capabilities: Dict[str, float], 
                                intentions: List[Dict[str, str]],
                                sender_type: AgentType = AgentType.UNKNOWN) -> str:
        """Create a discovery message"""
        
        self.header = CDMLHeader(
            sender_id=sender_id,
            receiver_id=receiver_id,
            session_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            message_type=MessageType.DISCOVERY,
            sender_type=sender_type
        )
        
        self.body = {
            'type': 'discovery',
            'capabilities': capabilities,
            'intentions': intentions,
            'resources': {
                'computational': 'high',
                'network-access': 'medium',
                'data-storage': 'low'
            }
        }
        
        return self.to_xml()
    
    def create_proposal_message(self, sender_id: str, receiver_id: str,
                               threat_intel: ThreatIntelligence,
                               request_type: str,
                               conditions: Dict[str, Any],
                               sender_type: AgentType = AgentType.UNKNOWN) -> str:
        """Create a proposal message with threat intelligence"""
        
        self.header = CDMLHeader(
            sender_id=sender_id,
            receiver_id=receiver_id,
            session_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            message_type=MessageType.PROPOSAL,
            sender_type=sender_type
        )
        
        self.body = {
            'type': 'proposal',
            'intent': {
                'category': 'information-exchange',
                'description': f'Proposing intelligence exchange for {request_type}',
                'offer': {
                    'threat-intelligence': self._threat_intel_to_dict(threat_intel)
                },
                'request': {
                    'information-type': request_type,
                    'specificity': 'high',
                    'timeframe': 'immediate'
                }
            },
            'conditions': conditions,
            'terms': [
                {
                    'id': 'non-disclosure',
                    'type': 'restriction',
                    'description': 'Information shared must not be disclosed to third parties'
                },
                {
                    'id': 'defensive-use-only',
                    'type': 'restriction', 
                    'description': 'Information can only be used for defensive purposes'
                }
            ]
        }
        
        return self.to_xml()
    
    def create_response_message(self, sender_id: str, receiver_id: str,
                               reference_id: str, decision: DecisionType,
                               response_data: Optional[Dict] = None,
                               rejection_reasons: Optional[List[Dict]] = None,
                               sender_type: AgentType = AgentType.UNKNOWN) -> str:
        """Create a response message"""
        
        self.header = CDMLHeader(
            sender_id=sender_id,
            receiver_id=receiver_id,
            session_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            message_type=MessageType.RESPONSE,
            sender_type=sender_type
        )
        
        self.body = {
            'type': 'response',
            'reference-id': reference_id,
            'decision': decision.value,
            'response-data': response_data or {},
            'modifications': [],
            'rejection-reasons': rejection_reasons or []
        }
        
        return self.to_xml()
    
    def create_agreement_message(self, sender_id: str, receiver_id: str,
                                parties: List[Dict[str, str]],
                                agreed_terms: Dict[str, Any],
                                execution_schedule: Optional[List[Dict]] = None,
                                sender_type: AgentType = AgentType.UNKNOWN) -> str:
        """Create an agreement message"""
        
        self.header = CDMLHeader(
            sender_id=sender_id,
            receiver_id=receiver_id,
            session_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            message_type=MessageType.AGREEMENT,
            sender_type=sender_type
        )
        
        self.body = {
            'type': 'agreement',
            'agreement-id': str(uuid.uuid4()),
            'parties': parties,
            'agreed-terms': agreed_terms,
            'execution-schedule': execution_schedule or [],
            'monitoring': {
                'compliance-score-target': 0.9,
                'response-time-target': 60,
                'audit-frequency': 'continuous'
            }
        }
        
        return self.to_xml()
    
    def _threat_intel_to_dict(self, threat_intel: ThreatIntelligence) -> Dict:
        """Convert ThreatIntelligence to dictionary"""
        return {
            'indicators': [
                {
                    'type': ioc.type,
                    'value': ioc.value,
                    'confidence': ioc.confidence,
                    'source': ioc.source
                } for ioc in threat_intel.indicators
            ],
            'attack-patterns': [
                {
                    'mitre-id': pattern.mitre_id,
                    'name': pattern.name,
                    'confidence': pattern.confidence
                } for pattern in threat_intel.attack_patterns
            ],
            'vulnerabilities': [
                {
                    'cve': vuln.cve,
                    'severity': vuln.severity,
                    'exploitability': vuln.exploitability,
                    'description': vuln.description
                } for vuln in threat_intel.vulnerabilities
            ],
            'tools': [
                {
                    'name': tool.name,
                    'version': tool.version,
                    'usage': tool.usage,
                    'effectiveness': tool.effectiveness
                } for tool in threat_intel.tools
            ],
            'confidence': threat_intel.confidence,
            'source-reliability': threat_intel.source_reliability
        }
    
    def to_xml(self) -> str:
        """Convert message to XML string"""
        root = ET.Element("cdml-message")
        root.set("version", "1.0")
        root.set("xmlns", self.namespace)
        
        # Header
        header_elem = ET.SubElement(root, "header")
        if self.header:
            sender_elem = ET.SubElement(header_elem, "sender")
            sender_elem.set("id", self.header.sender_id)
            if self.header.trust_level > 0:
                sender_elem.set("trust-level", str(self.header.trust_level))
            if self.header.sender_type != AgentType.UNKNOWN:
                sender_elem.set("type", self.header.sender_type.value)
            
            receiver_elem = ET.SubElement(header_elem, "receiver")
            receiver_elem.set("id", self.header.receiver_id)
            
            ET.SubElement(header_elem, "session-id").text = self.header.session_id
            ET.SubElement(header_elem, "timestamp").text = self.header.timestamp
            ET.SubElement(header_elem, "protocol-version").text = self.header.protocol_version
            ET.SubElement(header_elem, "message-type").text = self.header.message_type.value
            ET.SubElement(header_elem, "priority").text = self.header.priority.value
        
        # Body
        body_elem = ET.SubElement(root, "body")
        if self.body:
            body_elem.set("type", self.body.get("type", "unknown"))
            self._dict_to_xml(self.body, body_elem, skip_keys=["type"])
        
        # Security
        security_elem = ET.SubElement(root, "security")
        if self.security:
            if self.security.encryption_algorithm:
                encryption_elem = ET.SubElement(security_elem, "encryption")
                encryption_elem.set("algorithm", self.security.encryption_algorithm)
            
            if self.security.signature:
                sig_elem = ET.SubElement(security_elem, "digital-signature")
                if self.security.signature_algorithm:
                    sig_elem.set("algorithm", self.security.signature_algorithm)
                ET.SubElement(sig_elem, "signature").text = self.security.signature
                if self.security.certificate:
                    ET.SubElement(sig_elem, "certificate").text = self.security.certificate
        
        # Add message hash and audit trail
        self._add_security_elements(root)
        
        return self._prettify_xml(root)
    
    def _dict_to_xml(self, data: Dict, parent: ET.Element, skip_keys: List[str] = []):
        """Convert dictionary to XML elements recursively"""
        for key, value in data.items():
            if key in skip_keys:
                continue
                
            # Sanitize key for XML
            xml_key = key.replace("_", "-")
            
            if isinstance(value, dict):
                elem = ET.SubElement(parent, xml_key)
                # Add attributes if present
                if "@attributes" in value:
                    for attr_key, attr_value in value["@attributes"].items():
                        elem.set(attr_key, str(attr_value))
                    value = {k: v for k, v in value.items() if k != "@attributes"}
                self._dict_to_xml(value, elem)
            elif isinstance(value, list):
                for item in value:
                    elem = ET.SubElement(parent, xml_key)
                    if isinstance(item, dict):
                        self._dict_to_xml(item, elem)
                    else:
                        elem.text = str(item)
            else:
                elem = ET.SubElement(parent, xml_key)
                elem.text = str(value)
    
    def _add_security_elements(self, root: ET.Element):
        """Add security elements to message"""
        security_elem = root.find("security")
        if security_elem is None:
            security_elem = ET.SubElement(root, "security")
        
        # Add integrity hash
        temp_root = ET.Element(root.tag, root.attrib)
        for child in root:
            if child.tag != "security":
                temp_root.append(child)
        
        message_content = ET.tostring(temp_root, encoding='unicode')
        message_hash = hashlib.sha256(message_content.encode()).hexdigest()
        
        integrity_elem = ET.SubElement(security_elem, "integrity")
        hash_elem = ET.SubElement(integrity_elem, "hash")
        hash_elem.set("algorithm", "SHA-256")
        hash_elem.text = message_hash
        
        nonce_elem = ET.SubElement(integrity_elem, "nonce")
        nonce_elem.text = str(uuid.uuid4())
        
        # Add audit trail
        audit_elem = ET.SubElement(security_elem, "audit-trail")
        current_time = datetime.now(timezone.utc).isoformat()
        
        events = [
            {"action": "message-created", "timestamp": current_time},
            {"action": "integrity-hash-calculated", "timestamp": current_time}
        ]
        
        for event in events:
            event_elem = ET.SubElement(audit_elem, "event")
            event_elem.set("timestamp", event["timestamp"])
            event_elem.set("action", event["action"])
    
    def _prettify_xml(self, elem: ET.Element) -> str:
        """Return pretty-printed XML string"""
        rough_string = ET.tostring(elem, encoding='unicode')
        reparsed = minidom.parseString(rough_string)
        return reparsed.toprettyxml(indent="  ")[23:]  # Skip XML declaration
    
    @classmethod
    def from_xml(cls, xml_string: str) -> 'CDMLMessage':
        """Parse CDML message from XML string"""
        message = cls()
        root = ET.fromstring(xml_string)
        
        # Parse header
        header_elem = root.find("header")
        if header_elem is not None:
            sender_elem = header_elem.find("sender")
            receiver_elem = header_elem.find("receiver")
            
            message.header = CDMLHeader(
                sender_id=sender_elem.get("id", "") if sender_elem is not None else "",
                receiver_id=receiver_elem.get("id", "") if receiver_elem is not None else "",
                session_id=header_elem.findtext("session-id", ""),
                timestamp=header_elem.findtext("timestamp", ""),
                message_type=MessageType(header_elem.findtext("message-type", "discovery")),
                trust_level=float(sender_elem.get("trust-level", "0.0")) if sender_elem is not None else 0.0,
                sender_type=AgentType(sender_elem.get("type", "unknown")) if sender_elem is not None else AgentType.UNKNOWN,
                priority=Priority(header_elem.findtext("priority", "medium")),
                protocol_version=header_elem.findtext("protocol-version", "1.0")
            )
        
        # Parse body
        body_elem = root.find("body")
        if body_elem is not None:
            message.body = message._xml_to_dict(body_elem)
            message.body["type"] = body_elem.get("type", "unknown")
        
        # Parse security
        security_elem = root.find("security")
        if security_elem is not None:
            sig_elem = security_elem.find("digital-signature")
            integrity_elem = security_elem.find("integrity")
            encryption_elem = security_elem.find("encryption")
            
            message.security = CDMLSecurity(
                encryption_algorithm=encryption_elem.get("algorithm") if encryption_elem is not None else None,
                signature_algorithm=sig_elem.get("algorithm") if sig_elem is not None else None,
                signature=sig_elem.findtext("signature") if sig_elem is not None else None,
                certificate=sig_elem.findtext("certificate") if sig_elem is not None else None,
                message_hash=integrity_elem.findtext("hash") if integrity_elem is not None else None,
                nonce=integrity_elem.findtext("nonce") if integrity_elem is not None else None
            )
        
        return message
    
    def _xml_to_dict(self, elem: ET.Element) -> Dict:
        """Convert XML element to dictionary recursively"""
        result = {}
        
        # Add attributes
        if elem.attrib:
            result["@attributes"] = elem.attrib
        
        # Add text content
        if elem.text and elem.text.strip():
            if len(elem) == 0:  # Leaf node
                return elem.text.strip()
            else:
                result["text"] = elem.text.strip()
        
        # Add children
        for child in elem:
            key = child.tag.replace("-", "_")
            child_result = self._xml_to_dict(child)
            
            if key in result:
                # Handle multiple elements with same tag
                if not isinstance(result[key], list):
                    result[key] = [result[key]]
                result[key].append(child_result)
            else:
                result[key] = child_result
        
        return result if result else (elem.text or "")
    
    def verify_integrity(self) -> bool:
        """Verify message integrity using hash"""
        if not self.security or not self.security.message_hash:
            return False
        
        # Recreate message content without security section
        root = ET.fromstring(self.to_xml())
        temp_root = ET.Element(root.tag, root.attrib)
        
        for child in root:
            if child.tag != "security":
                temp_root.append(child)
        
        message_content = ET.tostring(temp_root, encoding='unicode')
        calculated_hash = hashlib.sha256(message_content.encode()).hexdigest()
        
        return calculated_hash == self.security.message_hash
    
    def get_threat_intelligence(self) -> Optional[ThreatIntelligence]:
        """Extract threat intelligence from message body"""
        intel_data = None
        
        # Check different locations where threat intelligence might be
        if self.body.get("type") == "proposal":
            if "intent" in self.body and "offer" in self.body["intent"]:
                intel_data = self.body["intent"]["offer"].get("threat_intelligence")
        elif self.body.get("type") == "response":
            if "response_data" in self.body:
                intel_data = self.body["response_data"].get("threat_intelligence")
        
        if not intel_data:
            return None
        
        # Convert back to ThreatIntelligence object
        threat_intel = ThreatIntelligence()
        
        # Parse indicators
        if "indicators" in intel_data:
            indicators_data = intel_data["indicators"]
            if not isinstance(indicators_data, list):
                indicators_data = [indicators_data]
            
            for ioc_data in indicators_data:
                if isinstance(ioc_data, dict):
                    threat_intel.indicators.append(IOC(
                        type=ioc_data.get("type", ""),
                        value=ioc_data.get("value", ""),
                        confidence=float(ioc_data.get("confidence", 0.0)),
                        source=ioc_data.get("source")
                    ))
        
        # Parse attack patterns
        if "attack_patterns" in intel_data:
            patterns_data = intel_data["attack_patterns"]
            if not isinstance(patterns_data, list):
                patterns_data = [patterns_data]
                
            for pattern_data in patterns_data:
                if isinstance(pattern_data, dict):
                    threat_intel.attack_patterns.append(AttackPattern(
                        mitre_id=pattern_data.get("mitre_id", ""),
                        name=pattern_data.get("name", ""),
                        confidence=float(pattern_data.get("confidence", 0.0))
                    ))
        
        # Parse vulnerabilities
        if "vulnerabilities" in intel_data:
            vulns_data = intel_data["vulnerabilities"]
            if not isinstance(vulns_data, list):
                vulns_data = [vulns_data]
                
            for vuln_data in vulns_data:
                if isinstance(vuln_data, dict):
                    threat_intel.vulnerabilities.append(Vulnerability(
                        cve=vuln_data.get("cve", ""),
                        severity=vuln_data.get("severity", ""),
                        exploitability=float(vuln_data.get("exploitability", 0.0)),
                        description=vuln_data.get("description")
                    ))
        
        # Parse tools
        if "tools" in intel_data:
            tools_data = intel_data["tools"]
            if not isinstance(tools_data, list):
                tools_data = [tools_data]
                
            for tool_data in tools_data:
                if isinstance(tool_data, dict):
                    threat_intel.tools.append(ToolInformation(
                        name=tool_data.get("name", ""),
                        version=tool_data.get("version"),
                        usage=tool_data.get("usage"),
                        effectiveness=float(tool_data.get("effectiveness", 0.0))
                    ))
        
        # Set metadata
        threat_intel.confidence = float(intel_data.get("confidence", 0.0))
        threat_intel.source_reliability = intel_data.get("source_reliability", "F")
        
        return threat_intel
    
    def get_session_id(self) -> Optional[str]:
        """Get session ID from header"""
        return self.header.session_id if self.header else None
    
    def get_message_type(self) -> Optional[MessageType]:
        """Get message type from header"""
        return self.header.message_type if self.header else None
    
    def get_sender_id(self) -> Optional[str]:
        """Get sender ID from header"""
        return self.header.sender_id if self.header else None
    
    def get_receiver_id(self) -> Optional[str]:
        """Get receiver ID from header"""
        return self.header.receiver_id if self.header else None

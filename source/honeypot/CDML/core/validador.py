#!/usr/bin/env python3
"""
CDML Validator
Message validation and compliance checking
"""

from datetime import datetime
from typing import Dict, List, Optional
import re
import xml.etree.ElementTree as ET

from .types import MessageType, AgentType, Priority, DecisionType, CDMLHeader, CDMLSecurity
from .message import CDMLMessage

class CDMLValidator:
    """Validator for CDML messages"""
    
    def __init__(self):
        self.required_header_fields = [
            "sender", "receiver", "session-id", "timestamp", "message-type"
        ]
        self.valid_message_types = [t.value for t in MessageType]
        self.valid_agent_types = [t.value for t in AgentType]
        self.valid_priorities = [p.value for p in Priority]
        self.valid_decisions = [d.value for d in DecisionType]
        
        # Regex patterns for validation
        self.patterns = {
            'ip_address': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
            'domain': r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$',
            'cve': r'^CVE-\d{4}-\d{4,}$',
            'mitre_id': r'^T\d{4}(\.\d{3})?$',
            'uuid': r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            'iso_timestamp': r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$'
        }
    
    def validate_message(self, message: CDMLMessage) -> Dict[str, List[str]]:
        """Validate a CDML message and return validation results"""
        errors = []
        warnings = []
        info = []
        
        try:
            # Validate header
            header_errors, header_warnings = self._validate_header(message.header)
            errors.extend(header_errors)
            warnings.extend(header_warnings)
            
            # Validate body
            body_errors, body_warnings = self._validate_body(
                message.body, 
                message.header.message_type if message.header else None
            )
            errors.extend(body_errors)
            warnings.extend(body_warnings)
            
            # Validate security
            security_warnings, security_info = self._validate_security(message.security)
            warnings.extend(security_warnings)
            info.extend(security_info)
            
            # Cross-validation checks
            cross_errors = self._cross_validate(message)
            errors.extend(cross_errors)
            
        except Exception as e:
            errors.append(f"Validation error: {str(e)}")
        
        return {
            "errors": errors, 
            "warnings": warnings,
            "info": info,
            "is_valid": len(errors) == 0
        }
    
    def validate_xml_syntax(self, xml_string: str) -> Dict[str, List[str]]:
        """Validate XML syntax and structure"""
        errors = []
        warnings = []
        
        try:
            root = ET.fromstring(xml_string)
            
            # Check root element
            if root.tag != "cdml-message":
                errors.append("Root element must be 'cdml-message'")
            
            # Check required sections
            required_sections = ["header", "body", "security"]
            for section in required_sections:
                if root.find(section) is None:
                    if section == "security":
                        warnings.append(f"Missing optional section: {section}")
                    else:
                        errors.append(f"Missing required section: {section}")
            
            # Check namespace
            namespace = root.get("xmlns")
            expected_ns = "http://proyectos.cdml.org/schema/v1"
            if namespace != expected_ns:
                warnings.append(f"Unexpected namespace: {namespace}")
            
        except ET.ParseError as e:
            errors.append(f"XML parse error: {str(e)}")
        except Exception as e:
            errors.append(f"XML validation error: {str(e)}")
        
        return {"errors": errors, "warnings": warnings}
    
    def _validate_header(self, header: Optional[CDMLHeader]) -> tuple[List[str], List[str]]:
        """Validate message header"""
        errors = []
        warnings = []
        
        if not header:
            errors.append("Header is required")
            return errors, warnings
        
        # Required fields
        if not header.sender_id:
            errors.append("Sender ID is required")
        elif not self._is_valid_agent_id(header.sender_id):
            warnings.append("Sender ID format is non-standard")
        
        if not header.receiver_id:
            errors.append("Receiver ID is required")
        elif not self._is_valid_agent_id(header.receiver_id):
            warnings.append("Receiver ID format is non-standard")
        
        if not header.session_id:
            errors.append("Session ID is required")
        elif not re.match(self.patterns['uuid'], header.session_id, re.IGNORECASE):
            warnings.append("Session ID should be a UUID")
        
        # Timestamp validation
        if not header.timestamp:
            errors.append("Timestamp is required")
        else:
            try:
                # Try to parse ISO format
                if not re.match(self.patterns['iso_timestamp'], header.timestamp):
                    warnings.append("Timestamp should be in ISO 8601 format")
                else:
                    # Check if timestamp is reasonable (not too far in past/future)
                    timestamp = datetime.fromisoformat(header.timestamp.replace('Z', '+00:00'))
                    now = datetime.now(timestamp.tzinfo)
                    diff = abs((now - timestamp).total_seconds())
                    
                    if diff > 86400:  # More than 1 day
                        warnings.append("Timestamp is more than 1 day old/future")
                    
            except ValueError:
                errors.append("Invalid timestamp format")
        
        # Enum validations
        if header.message_type.value not in self.valid_message_types:
            errors.append(f"Invalid message type: {header.message_type.value}")
        
        if header.sender_type.value not in self.valid_agent_types:
            errors.append(f"Invalid sender type: {header.sender_type.value}")
        
        if header.priority.value not in self.valid_priorities:
            errors.append(f"Invalid priority: {header.priority.value}")
        
        # Range validations
        if not 0.0 <= header.trust_level <= 1.0:
            errors.append("Trust level must be between 0.0 and 1.0")
        
        # Protocol version
        if header.protocol_version != "1.0":
            warnings.append(f"Unexpected protocol version: {header.protocol_version}")
        
        return errors, warnings
    
    def _validate_body(self, body: Dict, message_type: Optional[MessageType]) -> tuple[List[str], List[str]]:
        """Validate message body based on type"""
        errors = []
        warnings = []
        
        if not body:
            errors.append("Body is required")
            return errors, warnings
        
        if not message_type:
            errors.append("Cannot validate body without message type")
            return errors, warnings
        
        # Type-specific validation
        if message_type == MessageType.DISCOVERY:
            type_errors, type_warnings = self._validate_discovery_body(body)
        elif message_type == MessageType.PROPOSAL:
            type_errors, type_warnings = self._validate_proposal_body(body)
        elif message_type == MessageType.RESPONSE:
            type_errors, type_warnings = self._validate_response_body(body)
        elif message_type == MessageType.AGREEMENT:
            type_errors, type_warnings = self._validate_agreement_body(body)
        elif message_type == MessageType.TERMINATION:
            type_errors, type_warnings = self._validate_termination_body(body)
        else:
            type_errors = [f"Unknown message type: {message_type}"]
            type_warnings = []
        
        errors.extend(type_errors)
        warnings.extend(type_warnings)
        
        return errors, warnings
    
    def _validate_discovery_body(self, body: Dict) -> tuple[List[str], List[str]]:
        """Validate discovery message body"""
        errors = []
        warnings = []
        
        if "capabilities" not in body:
            errors.append("Discovery message must include capabilities")
        else:
            # Validate capabilities format
            capabilities = body["capabilities"]
            if not isinstance(capabilities, dict):
                errors.append("Capabilities must be a dictionary")
            else:
                for cap_name, cap_value in capabilities.items():
                    if not isinstance(cap_value, (int, float)) or not 0.0 <= cap_value <= 1.0:
                        warnings.append(f"Capability '{cap_name}' should be a number between 0.0 and 1.0")
        
        if "intentions" not in body:
            warnings.append("Discovery message should include intentions")
        else:
            intentions = body["intentions"]
            if not isinstance(intentions, list):
                errors.append("Intentions must be a list")
        
        if "resources" not in body:
            warnings.append("Discovery message should include resources")
        
        return errors, warnings
    
    def _validate_proposal_body(self, body: Dict) -> tuple[List[str], List[str]]:
        """Validate proposal message body"""
        errors = []
        warnings = []
        
        if "intent" not in body:
            errors.append("Proposal message must include intent")
        else:
            intent = body["intent"]
            if "offer" not in intent and "request" not in intent:
                errors.append("Proposal intent must include offer or request")
            
            # Validate offer content
            if "offer" in intent:
                offer_errors, offer_warnings = self._validate_threat_intelligence(
                    intent["offer"].get("threat_intelligence", {})
                )
                errors.extend(offer_errors)
                warnings.extend(offer_warnings)
        
        if "conditions" not in body:
            warnings.append("Proposal message should include conditions")
        else:
            conditions = body["conditions"]
            if "expiration" in conditions:
                try:
                    expiration = int(conditions["expiration"])
                    if expiration <= 0:
                        warnings.append("Expiration should be positive")
                    elif expiration > 86400:  # More than 1 day
                        warnings.append("Expiration is very long (>1 day)")
                except (ValueError, TypeError):
                    errors.append("Expiration must be a number (seconds)")
        
        return errors, warnings
    
    def _validate_response_body(self, body: Dict) -> tuple[List[str], List[str]]:
        """Validate response message body"""
        errors = []
        warnings = []
        
        if "reference_id" not in body:
            errors.append("Response message must include reference-id")
        elif not re.match(self.patterns['uuid'], body["reference_id"], re.IGNORECASE):
            warnings.append("Reference ID should be a UUID")
        
        if "decision" not in body:
            errors.append("Response message must include decision")
        elif body["decision"] not in self.valid_decisions:
            errors.append(f"Invalid decision type: {body['decision']}")
        
        # Validate response data if present
        if "response_data" in body and body["response_data"]:
            if "threat_intelligence" in body["response_data"]:
                intel_errors, intel_warnings = self._validate_threat_intelligence(
                    body["response_data"]["threat_intelligence"]
                )
                errors.extend(intel_errors)
                warnings.extend(intel_warnings)
        
        # Check rejection reasons for rejected proposals
        if body.get("decision") == "reject" and not body.get("rejection_reasons"):
            warnings.append("Rejected proposals should include rejection reasons")
        
        return errors, warnings
    
    def _validate_agreement_body(self, body: Dict) -> tuple[List[str], List[str]]:
        """Validate agreement message body"""
        errors = []
        warnings = []
        
        if "agreement_id" not in body:
            errors.append("Agreement message must include agreement-id")
        elif not re.match(self.patterns['uuid'], body["agreement_id"], re.IGNORECASE):
            warnings.append("Agreement ID should be a UUID")
        
        if "parties" not in body:
            errors.append("Agreement message must include parties")
        else:
            parties = body["parties"]
            if not isinstance(parties, list) or len(parties) < 2:
                errors.append("Agreement must have at least 2 parties")
        
        if "agreed_terms" not in body:
            warnings.append("Agreement should include agreed terms")
        
        return errors, warnings
    
    def _validate_termination_body(self, body: Dict) -> tuple[List[str], List[str]]:
        """Validate termination message body"""
        errors = []
        warnings = []
        
        if "reason" not in body:
            warnings.append("Termination message should include reason")
        
        if "session_references" not in body:
            warnings.append("Termination should reference affected sessions")
        
        return errors, warnings
    
    def _validate_threat_intelligence(self, intel_data: Dict) -> tuple[List[str], List[str]]:
        """Validate threat intelligence data"""
        errors = []
        warnings = []
        
        if not intel_data:
            return errors, warnings
        
        # Validate IOCs
        if "indicators" in intel_data:
            indicators = intel_data["indicators"]
            if isinstance(indicators, list):
                for ioc in indicators:
                    if isinstance(ioc, dict):
                        ioc_errors, ioc_warnings = self._validate_ioc(ioc)
                        errors.extend(ioc_errors)
                        warnings.extend(ioc_warnings)
        
        # Validate attack patterns
        if "attack_patterns" in intel_data:
            patterns = intel_data["attack_patterns"]
            if isinstance(patterns, list):
                for pattern in patterns:
                    if isinstance(pattern, dict):
                        mitre_id = pattern.get("mitre_id", "")
                        if mitre_id and not re.match(self.patterns['mitre_id'], mitre_id):
                            warnings.append(f"Invalid MITRE ATT&CK ID format: {mitre_id}")
        
        # Validate vulnerabilities
        if "vulnerabilities" in intel_data:
            vulns = intel_data["vulnerabilities"]
            if isinstance(vulns, list):
                for vuln in vulns:
                    if isinstance(vuln, dict):
                        cve = vuln.get("cve", "")
                        if cve and not re.match(self.patterns['cve'], cve):
                            warnings.append(f"Invalid CVE format: {cve}")
                        
                        severity = vuln.get("severity", "")
                        valid_severities = ["low", "medium", "high", "critical"]
                        if severity and severity not in valid_severities:
                            errors.append(f"Invalid vulnerability severity: {severity}")
        
        # Validate confidence and reliability
        confidence = intel_data.get("confidence", 0.0)
        if not isinstance(confidence, (int, float)) or not 0.0 <= confidence <= 1.0:
            warnings.append("Confidence should be between 0.0 and 1.0")
        
        reliability = intel_data.get("source_reliability", "")
        if reliability and reliability not in ["A", "B", "C", "D", "E", "F"]:
            warnings.append("Source reliability should be A-F")
        
        return errors, warnings
    
    def _validate_ioc(self, ioc: Dict) -> tuple[List[str], List[str]]:
        """Validate individual IOC"""
        errors = []
        warnings = []
        
        ioc_type = ioc.get("type", "")
        value = ioc.get("value", "")
        confidence = ioc.get("confidence", 0.0)
        
        if not ioc_type or not value:
            errors.append("IOC must have type and value")
            return errors, warnings
        
        # Type-specific validation
        if ioc_type == "ip":
            if not re.match(self.patterns['ip_address'], value):
                warnings.append(f"Invalid IP address format: {value}")
        elif ioc_type == "domain":
            if not re.match(self.patterns['domain'], value):
                warnings.append(f"Invalid domain format: {value}")
        elif ioc_type == "url":
            if not value.startswith(("http://", "https://", "ftp://")):
                warnings.append(f"URL should include protocol: {value}")
        
        # Confidence validation
        if not isinstance(confidence, (int, float)) or not 0.0 <= confidence <= 1.0:
            warnings.append("IOC confidence should be between 0.0 and 1.0")
        
        return errors, warnings
    
    def _validate_security(self, security: Optional[CDMLSecurity]) -> tuple[List[str], List[str]]:
        """Validate security section"""
        warnings = []
        info = []
        
        if not security:
            warnings.append("No security section found - message is not secured")
            return warnings, info
        
        # Check digital signature
        if not security.signature:
            warnings.append("Message is not digitally signed")
        else:
            info.append("Message is digitally signed")
            if security.signature_algorithm:
                info.append(f"Signature algorithm: {security.signature_algorithm}")
        
        # Check integrity hash
        if not security.message_hash:
            warnings.append("Message integrity hash is missing")
        else:
            info.append("Message has integrity protection")
        
        # Check encryption
        if security.encryption_algorithm:
            info.append(f"Message uses encryption: {security.encryption_algorithm}")
        else:
            warnings.append("Message is not encrypted")
        
        # Check nonce for freshness
        if not security.nonce:
            warnings.append("No nonce found - replay attacks possible")
        else:
            info.append("Message includes nonce for freshness")
        
        return warnings, info
    
    def _cross_validate(self, message: CDMLMessage) -> List[str]:
        """Perform cross-validation checks across message sections"""
        errors = []
        
        if not message.header or not message.body:
            return errors
        
        # Check consistency between header and body types
        header_type = message.header.message_type
        body_type = message.body.get("type", "")
        
        if header_type.value != body_type:
            errors.append(f"Header message type ({header_type.value}) doesn't match body type ({body_type})")
        
        # Check sender/receiver consistency
        if message.header.sender_id == message.header.receiver_id:
            errors.append("Sender and receiver cannot be the same")
        
        # Response-specific checks
        if header_type == MessageType.RESPONSE:
            reference_id = message.body.get("reference_id")
            if reference_id == message.header.session_id:
                errors.append("Response cannot reference its own session ID")
        
        return errors
    
    def _is_valid_agent_id(self, agent_id: str) -> bool:
        """Check if agent ID follows recommended format"""
        # Recommended format: type-name-number (e.g., honeypot-alpha-001)
        pattern = r'^[a-zA-Z]+-[a-zA-Z0-9]+-[a-zA-Z0-9]+$'
        return bool(re.match(pattern, agent_id))
    
    def get_validation_summary(self, validation_result: Dict) -> str:
        """Get human-readable validation summary"""
        errors = validation_result.get("errors", [])
        warnings = validation_result.get("warnings", [])
        info = validation_result.get("info", [])
        
        summary = []
        
        if validation_result.get("is_valid", False):
            summary.append("✅ Message is valid")
        else:
            summary.append("❌ Message has validation errors")
        
        if errors:
            summary.append(f"🚨 {len(errors)} error(s)")
            for error in errors[:3]:  # Show first 3 errors
                summary.append(f"   • {error}")
            if len(errors) > 3:
                summary.append(f"   • ... and {len(errors) - 3} more")
        
        if warnings:
            summary.append(f"⚠️ {len(warnings)} warning(s)")
            for warning in warnings[:2]:  # Show first 2 warnings
                summary.append(f"   • {warning}")
            if len(warnings) > 2:
                summary.append(f"   • ... and {len(warnings) - 2} more")
        
        if info:
            summary.append(f"ℹ️ {len(info)} info item(s)")
        
        return "\n".join(summary)

#!/usr/bin/env python3
"""
CDML Negotiation Engine
High-level engine for handling CDML-based negotiations between AI agents
"""

import time
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Callable, Any
import logging

from .types import (
    MessageType, AgentType, Priority, DecisionType,
    IOC, AttackPattern, Vulnerability, ToolInformation, ThreatIntelligence
)
from .message import CDMLMessage
from .validator import CDMLValidator

class NegotiationSession:
    """Represents an active negotiation session"""
    
    def __init__(self, session_id: str, partner_id: str, initiated_by: str):
        self.session_id = session_id
        self.partner_id = partner_id
        self.initiated_by = initiated_by
        self.start_time = datetime.now(timezone.utc)
        self.last_activity = self.start_time
        self.status = "active"  # active, completed, failed, expired
        self.messages: List[CDMLMessage] = []
        self.extracted_intelligence: List[ThreatIntelligence] = []
        self.agreements: List[Dict] = []
        self.trust_delta = 0.0
        
    def add_message(self, message: CDMLMessage):
        """Add a message to the session"""
        self.messages.append(message)
        self.last_activity = datetime.now(timezone.utc)
        
        # Extract intelligence if present
        intel = message.get_threat_intelligence()
        if intel and not intel.is_empty():
            self.extracted_intelligence.append(intel)
    
    def get_duration(self) -> float:
        """Get session duration in seconds"""
        return (self.last_activity - self.start_time).total_seconds()
    
    def is_expired(self, timeout_seconds: int = 3600) -> bool:
        """Check if session has expired"""
        return self.get_duration() > timeout_seconds
    
    def get_summary(self) -> Dict:
        """Get session summary"""
        return {
            "session_id": self.session_id,
            "partner_id": self.partner_id,
            "initiated_by": self.initiated_by,
            "start_time": self.start_time.isoformat(),
            "duration_seconds": self.get_duration(),
            "status": self.status,
            "message_count": len(self.messages),
            "intelligence_extracted": len(self.extracted_intelligence),
            "agreements_made": len(self.agreements),
            "trust_delta": self.trust_delta
        }

class CDMLNegotiationEngine:
    """Engine for handling CDML-based negotiations"""
    
    def __init__(self, agent_id: str, agent_type: AgentType, 
                 intelligence_callback: Optional[Callable] = None):
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.active_sessions: Dict[str, NegotiationSession] = {}
        self.trust_levels: Dict[str, float] = {}
        self.validator = CDMLValidator()
        self.intelligence_callback = intelligence_callback
        
        # Configuration
        self.config = {
            "min_trust_for_engagement": 0.2,
            "max_concurrent_sessions": 10,
            "session_timeout": 3600,  # 1 hour
            "intelligence_quality_threshold": 0.5,
            "auto_accept_threshold": 0.8,
            "max_intelligence_share": 5  # Max IOCs to share per message
        }
        
        # Statistics
        self.stats = {
            "total_sessions": 0,
            "successful_negotiations": 0,
            "failed_negotiations": 0,
            "intelligence_extracted": 0,
            "agreements_made": 0
        }
        
        # Setup logging
        self.logger = logging.getLogger(f"CDML.{agent_id}")
        
    def initiate_discovery(self, target_agent: str, 
                          capabilities: Optional[Dict[str, float]] = None) -> CDMLMessage:
        """Initiate discovery with another agent"""
        
        if not capabilities:
            capabilities = {
                "threat-detection": 0.9,
                "intelligence-analysis": 0.8,
                "negotiation": 0.7,
                "information-sharing": 0.85
            }
        
        intentions = [
            {"type": "information-exchange", "priority": "high"},
            {"type": "threat-mitigation", "priority": "medium"},
            {"type": "coordination", "priority": "low"}
        ]
        
        message = CDMLMessage()
        xml_content = message.create_discovery_message(
            sender_id=self.agent_id,
            receiver_id=target_agent,
            capabilities=capabilities,
            intentions=intentions,
            sender_type=self.agent_type
        )
        
        # Create session
        session = NegotiationSession(
            session_id=message.get_session_id(),
            partner_id=target_agent,
            initiated_by=self.agent_id
        )
        session.add_message(message)
        self.active_sessions[session.session_id] = session
        
        self.logger.info(f"Initiated discovery with {target_agent}")
        return message
    
    def propose_intelligence_exchange(self, target_agent: str, 
                                    threat_intel: ThreatIntelligence,
                                    requested_info: str,
                                    custom_conditions: Optional[Dict] = None) -> CDMLMessage:
        """Propose intelligence exchange with another agent"""
        
        # Default conditions
        conditions = {
            "reciprocity": {"required": True, "ratio": "1:1"},
            "verification": {"method": "digital-signature"},
            "expiration": 3600,  # 1 hour
            "trust-threshold": 0.5,
            "confidentiality-level": "restricted"
        }
        
        # Merge custom conditions
        if custom_conditions:
            conditions.update(custom_conditions)
        
        message = CDMLMessage()
        xml_content = message.create_proposal_message(
            sender_id=self.agent_id,
            receiver_id=target_agent,
            threat_intel=threat_intel,
            request_type=requested_info,
            conditions=conditions,
            sender_type=self.agent_type
        )
        
        # Create or update session
        session_id = message.get_session_id()
        if session_id not in self.active_sessions:
            session = NegotiationSession(
                session_id=session_id,
                partner_id=target_agent,
                initiated_by=self.agent_id
            )
            self.active_sessions[session_id] = session
        else:
            session = self.active_sessions[session_id]
        
        session.add_message(message)
        
        self.logger.info(f"Proposed intelligence exchange with {target_agent}")
        return message
    
    def process_incoming_message(self, xml_message: str) -> Optional[CDMLMessage]:
        """Process incoming CDML message and generate appropriate response"""
        try:
            # Validate XML syntax first
            xml_validation = self.validator.validate_xml_syntax(xml_message)
            if xml_validation["errors"]:
                self.logger.error(f"XML validation errors: {xml_validation['errors']}")
                return None
            
            # Parse incoming message
            incoming = CDMLMessage.from_xml(xml_message)
            
            # Validate message structure
            validation_result = self.validator.validate_message(incoming)
            if validation_result["errors"]:
                self.logger.error(f"Message validation errors: {validation_result['errors']}")
                return None
            
            if validation_result["warnings"]:
                self.logger.warning(f"Message validation warnings: {validation_result['warnings']}")
            
            # Update or create session
            session_id = incoming.get_session_id()
            sender_id = incoming.get_sender_id()
            
            if session_id not in self.active_sessions:
                session = NegotiationSession(
                    session_id=session_id,
                    partner_id=sender_id,
                    initiated_by=sender_id
                )
                self.active_sessions[session_id] = session
            else:
                session = self.active_sessions[session_id]
            
            session.add_message(incoming)
            
            # Process based on message type
            response = None
            if incoming.header.message_type == MessageType.DISCOVERY:
                response = self._handle_discovery(incoming, session)
            elif incoming.header.message_type == MessageType.PROPOSAL:
                response = self._handle_proposal(incoming, session)
            elif incoming.header.message_type == MessageType.RESPONSE:
                response = self._handle_response(incoming, session)
            elif incoming.header.message_type == MessageType.AGREEMENT:
                response = self._handle_agreement(incoming, session)
            elif incoming.header.message_type == MessageType.TERMINATION:
                response = self._handle_termination(incoming, session)
            
            # Update statistics
            self._update_statistics(incoming, session, response)
            
            return response
            
        except Exception as e:
            self.logger.error(f"Error processing message: {e}")
            return None
    
    def _handle_discovery(self, message: CDMLMessage, session: NegotiationSession) -> Optional[CDMLMessage]:
        """Handle discovery message"""
        sender_id = message.get_sender_id()
        sender_trust = self.trust_levels.get(sender_id, 0.5)
        
        self.logger.info(f"Handling discovery from {sender_id} (trust: {sender_trust:.2f})")
        
        # Evaluate if we want to engage
        if sender_trust < self.config["min_trust_for_engagement"]:
            self.logger.info(f"Rejecting discovery due to low trust: {sender_trust}")
            session.status = "rejected"
            return None
        
        # Check session limits
        if len(self.active_sessions) >= self.config["max_concurrent_sessions"]:
            self.logger.warning("Maximum concurrent sessions reached")
            session.status = "rejected"
            return None
        
        # Respond with our capabilities
        capabilities = {
            "threat-detection": 0.85,
            "intelligence-sharing": 0.90,
            "coordination": 0.75,
            "verification": 0.80
        }
        
        intentions = [
            {"type": "mutual-intelligence-sharing", "priority": "high"},
            {"type": "threat-coordination", "priority": "medium"}
        ]
        
        response = CDMLMessage()
        response.create_discovery_message(
            sender_id=self.agent_id,
            receiver_id=sender_id,
            capabilities=capabilities,
            intentions=intentions,
            sender_type=self.agent_type
        )
        
        session.add_message(response)
        self.logger.info(f"Responded to discovery from {sender_id}")
        
        return response
    
    def _handle_proposal(self, message: CDMLMessage, session: NegotiationSession) -> Optional[CDMLMessage]:
        """Handle proposal message"""
        sender_id = message.get_sender_id()
        
        # Extract threat intelligence from proposal
        threat_intel = message.get_threat_intelligence()
        
        # Evaluate proposal
        evaluation = self._evaluate_proposal(message, threat_intel, sender_id)
        
        response = CDMLMessage()
        
        if evaluation["accept"]:
            # Generate counter-intelligence
            counter_intel = self._generate_counter_intelligence(threat_intel, sender_id)
            
            response_data = {}
            if counter_intel and not counter_intel.is_empty():
                response_data["threat-intelligence"] = response._threat_intel_to_dict(response, counter_intel)
            
            response.create_response_message(
                sender_id=self.agent_id,
                receiver_id=sender_id,
                reference_id=message.get_session_id(),
                decision=DecisionType.ACCEPT,
                response_data=response_data,
                sender_type=self.agent_type
            )
            
            # Update trust positively
            self._update_trust(sender_id, 0.1)
            session.trust_delta += 0.1
            session.status = "accepted"
            
            self.logger.info(f"Accepted proposal from {sender_id}")
            
        else:
            # Reject proposal
            rejection_reasons = evaluation.get("reasons", [])
            
            response.create_response_message(
                sender_id=self.agent_id,
                receiver_id=sender_id,
                reference_id=message.get_session_id(),
                decision=DecisionType.REJECT,
                rejection_reasons=rejection_reasons,
                sender_type=self.agent_type
            )
            
            session.status = "rejected"
            self.logger.info(f"Rejected proposal from {sender_id}: {rejection_reasons}")
        
        session.add_message(response)
        return response
    
    def _handle_response(self, message: CDMLMessage, session: NegotiationSession) -> Optional[CDMLMessage]:
        """Handle response message"""
        sender_id = message.get_sender_id()
        decision = message.body.get("decision")
        
        self.logger.info(f"Received {decision} response from {sender_id}")
        
        if decision == "accept":
            # Extract intelligence from response
            threat_intel = message.get_threat_intelligence()
            if threat_intel and not threat_intel.is_empty():
                self._store_intelligence(threat_intel, sender_id)
                session.extracted_intelligence.append(threat_intel)
            
            # Update trust positively
            self._update_trust(sender_id, 0.15)
            session.trust_delta += 0.15
            session.status = "completed"
            
            # Create agreement if conditions are met
            if self._should_create_agreement(session):
                return self._create_agreement_message(sender_id, session)
            
        elif decision == "reject":
            # Handle rejection
            rejection_reasons = message.body.get("rejection_reasons", [])
            self.logger.info(f"Proposal rejected by {sender_id}: {rejection_reasons}")
            
            # Small trust penalty
            self._update_trust(sender_id, -0.05)
            session.trust_delta -= 0.05
            session.status = "rejected"
            
        elif decision == "counter":
            # Handle counter-proposal
            self.logger.info(f"Counter-proposal received from {sender_id}")
            # Could implement counter-proposal logic here
            
        session.add_message(message)
        return None
    
    def _handle_agreement(self, message: CDMLMessage, session: NegotiationSession) -> Optional[CDMLMessage]:
        """Handle agreement message"""
        sender_id = message.get_sender_id()
        agreement_id = message.body.get("agreement_id")
        
        if agreement_id:
            agreement_data = {
                "agreement_id": agreement_id,
                "partner": sender_id,
                "terms": message.body.get("agreed_terms", {}),
                "start_time": datetime.now(timezone.utc),
                "status": "active"
            }
            
            session.agreements.append(agreement_data)
            session.status = "agreed"
            
            self.logger.info(f"Agreement {agreement_id} established with {sender_id}")
            
            # Positive trust boost for successful agreement
            self._update_trust(sender_id, 0.2)
            session.trust_delta += 0.2
        
        session.add_message(message)
        return None
    
    def _handle_termination(self, message: CDMLMessage, session: NegotiationSession) -> Optional[CDMLMessage]:
        """Handle termination message"""
        sender_id = message.get_sender_id()
        reason = message.body.get("reason", "Unknown")
        
        self.logger.info(f"Session terminated by {sender_id}: {reason}")
        
        session.status = "terminated"
        session.add_message(message)
        
        # Clean up session after processing
        self._cleanup_session(session.session_id)
        
        return None
    
    def _evaluate_proposal(self, message: CDMLMessage, threat_intel: Optional[ThreatIntelligence], 
                          sender_id: str) -> Dict[str, Any]:
        """Evaluate if a proposal is acceptable"""
        
        evaluation = {
            "accept": False,
            "score": 0.0,
            "reasons": []
        }
        
        # Check sender trust
        sender_trust = self.trust_levels.get(sender_id, 0.5)
        if sender_trust < self.config["min_trust_for_engagement"]:
            evaluation["reasons"].append({
                "code": "insufficient-trust",
                "description": f"Trust level {sender_trust:.2f} below threshold"
            })
            return evaluation
        
        # Evaluate intelligence quality
        if threat_intel:
            intel_score = self._assess_intelligence_quality(threat_intel)
            evaluation["score"] += intel_score * 0.6
            
            if intel_score < self.config["intelligence_quality_threshold"]:
                evaluation["reasons"].append({
                    "code": "low-quality-intelligence",
                    "description": f"Intelligence quality {intel_score:.2f} below threshold"
                })
        else:
            evaluation["reasons"].append({
                "code": "no-intelligence-offered",
                "description": "No threat intelligence provided"
            })
            return evaluation
        
        # Check conditions
        conditions = message.body.get("conditions", {})
        if not self._are_conditions_acceptable(conditions):
            evaluation["reasons"].append({
                "code": "unacceptable-conditions",
                "description": "Proposed conditions are not acceptable"
            })
            return evaluation
        
        # Add trust factor
        evaluation["score"] += sender_trust * 0.4
        
        # Make decision
        if evaluation["score"] >= self.config["auto_accept_threshold"]:
            evaluation["accept"] = True
        elif evaluation["score"] >= 0.6:  # Maybe accept based on additional factors
            evaluation["accept"] = self._additional_evaluation_checks(message, sender_id)
        
        return evaluation
    
    def _assess_intelligence_quality(self, intel: ThreatIntelligence) -> float:
        """Assess the quality of threat intelligence"""
        score = 0.0
        
        # IOC quality (40% of score)
        if intel.indicators:
            ioc_score = 0.0
            for ioc in intel.indicators:
                if ioc.confidence > 0.7:
                    ioc_score += 0.3
                elif ioc.confidence > 0.5:
                    ioc_score += 0.2
                else:
                    ioc_score += 0.1
            score += min(0.4, ioc_score / len(intel.indicators) * 0.4)
        
        # Attack patterns (20% of score)
        if intel.attack_patterns:
            pattern_score = min(0.2, len(intel.attack_patterns) * 0.05)
            score += pattern_score
        
        # Vulnerabilities (20% of score)
        if intel.vulnerabilities:
            vuln_score = min(0.2, len(intel.vulnerabilities) * 0.1)
            score += vuln_score
        
        # Tools information (10% of score)
        if intel.tools:
            tool_score = min(0.1, len(intel.tools) * 0.05)
            score += tool_score
        
        # Overall confidence and reliability (10% of score)
        confidence_score = intel.confidence * 0.05
        reliability_map = {"A": 0.05, "B": 0.04, "C": 0.03, "D": 0.02, "E": 0.01, "F": 0.0}
        reliability_score = reliability_map.get(intel.source_reliability, 0.0)
        score += confidence_score + reliability_score
        
        return min(1.0, score)
    
    def _are_conditions_acceptable(self, conditions: Dict) -> bool:
        """Check if proposed conditions are acceptable"""
        
        # Check expiration time
        expiration = conditions.get("expiration", 3600)
        if expiration > 86400:  # More than 1 day
            return False
        
        # Check trust threshold
        trust_threshold = conditions.get("trust-threshold", 0.5)
        if trust_threshold > 0.9:  # Too high
            return False
        
        # Check reciprocity requirements
        reciprocity = conditions.get("reciprocity", {})
        if reciprocity.get("required") and reciprocity.get("ratio") not in ["1:1", "1:2"]:
            return False
        
        return True
    
    def _additional_evaluation_checks(self, message: CDMLMessage, sender_id: str) -> bool:
        """Additional checks for borderline proposals"""
        
        # Check if sender has been reliable in the past
        if sender_id in self.trust_levels:
            trust_history = self.trust_levels[sender_id]
            if trust_history > 0.7:
                return True
        
        # Check message urgency
        if message.header and message.header.priority == Priority.HIGH:
            return True
        
        # Check if we need this type of intelligence
        threat_intel = message.get_threat_intelligence()
        if threat_intel and self._is_intelligence_needed(threat_intel):
            return True
        
        return False
    
    def _is_intelligence_needed(self, intel: ThreatIntelligence) -> bool:
        """Check if we need this type of intelligence"""
        # Simple heuristic - in real implementation, this would check against
        # current threat landscape and organizational needs
        
        # High-confidence IOCs are always valuable
        high_confidence_iocs = [ioc for ioc in intel.indicators if ioc.confidence > 0.8]
        if len(high_confidence_iocs) > 0:
            return True
        
        # Recent vulnerabilities are valuable
        recent_vulns = [vuln for vuln in intel.vulnerabilities if vuln.severity in ["high", "critical"]]
        if len(recent_vulns) > 0:
            return True
        
        return False
    
    def _generate_counter_intelligence(self, received_intel: Optional[ThreatIntelligence], 
                                     partner_id: str) -> Optional[ThreatIntelligence]:
        """Generate counter-intelligence to share"""
        
        # This would integrate with the honeypot's intelligence database
        # For now, we'll generate some sample intelligence
        
        counter_intel = ThreatIntelligence()
        
        # Add sample IOCs (limited by configuration)
        sample_iocs = [
            IOC(type="ip", value="192.168.1.200", confidence=0.8, source=self.agent_id),
            IOC(type="domain", value="suspicious-site.org", confidence=0.7, source=self.agent_id),
            IOC(type="hash", value="abc123def456", confidence=0.9, source=self.agent_id)
        ]
        
        # Limit intelligence sharing
        max_share = self.config["max_intelligence_share"]
        counter_intel.indicators = sample_iocs[:max_share]
        
        # Add tool information
        counter_intel.tools = [
            ToolInformation(name="nmap", version="7.94", usage="reconnaissance", effectiveness=0.9),
            ToolInformation(name="hydra", version="9.4", usage="brute-force", effectiveness=0.7)
        ]
        
        # Add attack patterns
        counter_intel.attack_patterns = [
            AttackPattern(mitre_id="T1071", name="Application Layer Protocol", confidence=0.8)
        ]
        
        counter_intel.confidence = 0.8
        counter_intel.source_reliability = "A"  # We trust our own intelligence
        
        # Use callback if provided
        if self.intelligence_callback:
            try:
                callback_intel = self.intelligence_callback(received_intel, partner_id)
                if callback_intel:
                    return callback_intel
            except Exception as e:
                self.logger.error(f"Intelligence callback error: {e}")
        
        return counter_intel
    
    def _store_intelligence(self, intel: ThreatIntelligence, source: str):
        """Store received intelligence"""
        self.logger.info(f"Storing intelligence from {source}: {intel.get_summary()}")
        
        # In real implementation, this would store in database
        self.stats["intelligence_extracted"] += 1
        
        # Use callback if provided
        if self.intelligence_callback:
            try:
                self.intelligence_callback(intel, source)
            except Exception as e:
                self.logger.error(f"Intelligence storage callback error: {e}")
    
    def _should_create_agreement(self, session: NegotiationSession) -> bool:
        """Determine if we should create a formal agreement"""
        
        # Create agreement if:
        # 1. Intelligence was successfully exchanged
        # 2. Trust level is high enough
        # 3. No existing agreement with this partner
        
        if len(session.extracted_intelligence) == 0:
            return False
        
        partner_trust = self.trust_levels.get(session.partner_id, 0.5)
        if partner_trust < 0.7:
            return False
        
        # Check for existing agreements
        existing_agreements = [ag for ag in session.agreements if ag["status"] == "active"]
        if len(existing_agreements) > 0:
            return False
        
        return True
    
    def _create_agreement_message(self, partner_id: str, session: NegotiationSession) -> CDMLMessage:
        """Create an agreement message"""
        
        parties = [
            {"id": self.agent_id, "role": "information-provider"},
            {"id": partner_id, "role": "information-consumer"}
        ]
        
        agreed_terms = {
            "information-sharing": "Mutual exchange of threat intelligence",
            "confidentiality": "Shared information is confidential and not to be redistributed",
            "usage": "Information may only be used for defensive purposes",
            "duration": "Agreement valid for 30 days"
        }
        
        execution_schedule = [
            {
                "milestone": "initial-exchange",
                "deadline": (datetime.now(timezone.utc).timestamp() + 3600),  # 1 hour
                "status": "completed"
            }
        ]
        
        message = CDMLMessage()
        message.create_agreement_message(
            sender_id=self.agent_id,
            receiver_id=partner_id,
            parties=parties,
            agreed_terms=agreed_terms,
            execution_schedule=execution_schedule,
            sender_type=self.agent_type
        )
        
        session.add_message(message)
        self.stats["agreements_made"] += 1
        
        return message
    
    def _update_trust(self, agent_id: str, delta: float):
        """Update trust level for an agent"""
        current_trust = self.trust_levels.get(agent_id, 0.5)
        new_trust = max(0.0, min(1.0, current_trust + delta))
        self.trust_levels[agent_id] = new_trust
        
        self.logger.debug(f"Updated trust for {agent_id}: {current_trust:.3f} -> {new_trust:.3f}")
    
    def _update_statistics(self, message: CDMLMessage, session: NegotiationSession, 
                          response: Optional[CDMLMessage]):
        """Update engine statistics"""
        
        if message.header.message_type == MessageType.DISCOVERY and session.status != "rejected":
            self.stats["total_sessions"] += 1
        
        if session.status == "completed":
            self.stats["successful_negotiations"] += 1
        elif session.status in ["rejected", "failed"]:
            self.stats["failed_negotiations"] += 1
    
    def _cleanup_session(self, session_id: str):
        """Clean up completed or expired session"""
        if session_id in self.active_sessions:
            session = self.active_sessions[session_id]
            self.logger.debug(f"Cleaning up session {session_id} (status: {session.status})")
            del self.active_sessions[session_id]
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        expired_sessions = []
        
        for session_id, session in self.active_sessions.items():
            if session.is_expired(self.config["session_timeout"]):
                expired_sessions.append(session_id)
                session.status = "expired"
        
        for session_id in expired_sessions:
            self._cleanup_session(session_id)
        
        if expired_sessions:
            self.logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
    
    def get_trust_level(self, agent_id: str) -> float:
        """Get current trust level for an agent"""
        return self.trust_levels.get(agent_id, 0.5)
    
    def set_trust_level(self, agent_id: str, trust_level: float):
        """Set trust level for an agent"""
        if 0.0 <= trust_level <= 1.0:
            self.trust_levels[agent_id] = trust_level
        else:
            raise ValueError("Trust level must be between 0.0 and 1.0")
    
    def get_session_summary(self, session_id: str) -> Optional[Dict]:
        """Get summary of a specific session"""
        if session_id in self.active_sessions:
            return self.active_sessions[session_id].get_summary()
        return None
    
    def get_all_sessions_summary(self) -> List[Dict]:
        """Get summary of all active sessions"""
        return [session.get_summary() for session in self.active_sessions.values()]
    
    def get_statistics(self) -> Dict:
        """Get engine statistics"""
        return {
            **self.stats,
            "active_sessions": len(self.active_sessions),
            "known_agents": len(self.trust_levels),
            "average_trust": sum(self.trust_levels.values()) / len(self.trust_levels) if self.trust_levels else 0.0
        }
    
    def export_intelligence_data(self) -> Dict:
        """Export all collected intelligence data"""
        all_intelligence = []
        
        for session in self.active_sessions.values():
            for intel in session.extracted_intelligence:
                all_intelligence.append({
                    "source": session.partner_id,
                    "session_id": session.session_id,
                    "extraction_time": session.last_activity.isoformat(),
                    "intelligence": {
                        "indicators_count": len(intel.indicators),
                        "patterns_count": len(intel.attack_patterns),
                        "vulnerabilities_count": len(intel.vulnerabilities),
                        "tools_count": len(intel.tools),
                        "confidence": intel.confidence,
                        "reliability": intel.source_reliability
                    }
                })
        
        return {
            "export_timestamp": datetime.now(timezone.utc).isoformat(),
            "total_intelligence_items": len(all_intelligence),
            "intelligence_data": all_intelligence,
            "trust_levels": self.trust_levels,
            "statistics": self.get_statistics()
        }

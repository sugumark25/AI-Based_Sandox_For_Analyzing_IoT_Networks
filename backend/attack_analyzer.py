"""
backend/attack_analyzer.py
===========================
Analyzes detected attacks and generates appropriate blocking commands.

Attack types detected:
  - DDoS: High packet rate + large traffic volume
  - Port Scan: Low payload, rejected connections
  - Botnet C2: Unusual connection patterns + sustained flows
  - ICMP Sweep: ICMP traffic with rejected connections
"""

import logging
import numpy as np
from typing import Tuple, Optional

log = logging.getLogger("attack_analyzer")


class AttackAnalyzer:
    """Analyzes attack patterns and generates blocking recommendations."""
    
    # Attack thresholds
    DDOS_PKT_RATE_THRESHOLD = 500.0      # packets/sec
    DDOS_TRAFFIC_THRESHOLD = 1_000_000   # total bytes
    
    PORT_SCAN_PKT_THRESHOLD = 100        # suspicious low packet count
    PORT_SCAN_REJECTION_THRESHOLD = 0.5  # >50% rejected connections
    
    BOTNET_DURATION_THRESHOLD = 0.5      # seconds
    BOTNET_VARIANCE_THRESHOLD = 10.0     # high variance in traffic
    
    ICMP_SWEEP_THRESHOLD = 50            # ICMP packets with rejections
    
    @staticmethod
    def classify_attack(features: dict) -> Tuple[str, float, dict]:
        """
        Classify the type of attack based on network features.
        
        Returns:
            (attack_type, confidence, analysis_details)
        """
        packet_rate = float(features.get("packet_rate", 0))
        byte_rate = float(features.get("byte_rate", 0))
        duration = float(features.get("duration", 0))
        src_bytes = float(features.get("src_bytes", 0))
        dst_bytes = float(features.get("dst_bytes", 0))
        src_pkts = float(features.get("src_pkts", 0))
        dst_pkts = float(features.get("dst_pkts", 0))
        proto_tcp = int(features.get("proto_tcp", 0))
        proto_udp = int(features.get("proto_udp", 0))
        proto_icmp = int(features.get("proto_icmp", 0))
        conn_ok = float(features.get("conn_ok", 0))
        conn_s0 = float(features.get("conn_s0", 0))
        conn_rej = float(features.get("conn_rej", 0))
        variance = float(features.get("variance", 0))
        
        # Calculate total connections and rejection rate
        total_conn = conn_ok + conn_s0 + conn_rej
        rejection_rate = conn_rej / max(total_conn, 1)
        total_bytes = src_bytes + dst_bytes
        
        analysis = {
            "packet_rate": packet_rate,
            "byte_rate": byte_rate,
            "duration": duration,
            "total_bytes": total_bytes,
            "rejection_rate": rejection_rate,
            "variance": variance,
        }
        
        # DDoS Detection
        if packet_rate > AttackAnalyzer.DDOS_PKT_RATE_THRESHOLD:
            if total_bytes > AttackAnalyzer.DDOS_TRAFFIC_THRESHOLD:
                analysis["reason"] = "High packet rate + massive traffic"
                return "DDoS", 0.95, analysis
        
        if byte_rate > 100_000.0 and packet_rate > 100.0:
            analysis["reason"] = "Sustained high-rate traffic"
            return "DDoS", 0.85, analysis
        
        # ICMP Sweep Detection
        if proto_icmp and src_pkts > AttackAnalyzer.ICMP_SWEEP_THRESHOLD:
            if rejection_rate > 0.3:
                analysis["reason"] = "ICMP sweep with rejections"
                return "ICMP_Sweep", 0.90, analysis
        
        # Port Scan Detection
        if src_pkts < AttackAnalyzer.PORT_SCAN_PKT_THRESHOLD:
            if rejection_rate > AttackAnalyzer.PORT_SCAN_REJECTION_THRESHOLD:
                analysis["reason"] = "Low packets + high rejection rate"
                return "PortScan", 0.85, analysis
        
        if total_bytes < 500 and dst_pkts < 5:
            if proto_tcp or proto_udp:
                if conn_s0 > 0 or conn_rej > 0:
                    analysis["reason"] = "Small probe with no proper connection"
                    return "PortScan", 0.75, analysis
        
        # Botnet/C2 Detection
        if duration > AttackAnalyzer.BOTNET_DURATION_THRESHOLD:
            if variance > AttackAnalyzer.BOTNET_VARIANCE_THRESHOLD:
                analysis["reason"] = "Long flow + high traffic variance"
                return "Botnet_C2", 0.80, analysis
        
        if src_pkts > 50 and dst_pkts > 50:
            if byte_rate > 10_000.0:
                if conn_ok > 0 and (conn_s0 > 0 or conn_rej > 0):
                    analysis["reason"] = "Bi-directional traffic + mixed connections"
                    return "Botnet_C2", 0.70, analysis
        
        # Default: Generic attack
        analysis["reason"] = "Anomalous pattern detected"
        return "Generic_Attack", 0.60, analysis
    
    @staticmethod
    def generate_blocking_action(
        attack_type: str, 
        source_ip: Optional[str] = None,
        source_port: Optional[str] = None,
    ) -> Tuple[str, str]:
        """
        Generate blocking action based on attack type.
        
        Returns:
            (action, target)
            
        Example:
            ("block_ip", "192.168.1.100")
            ("block_port", "443")
            ("drop_traffic", "src_ip:192.168.1.100")
        """
        
        if attack_type == "DDoS":
            if source_ip:
                return ("block_ip", source_ip)
            return ("drop_traffic_pattern", "high_rate")
        
        elif attack_type == "PortScan":
            if source_ip:
                return ("block_ip", source_ip)
            return ("drop_traffic_pattern", "port_scan")
        
        elif attack_type == "ICMP_Sweep":
            if source_ip:
                return ("block_proto", f"{source_ip}:ICMP")
            return ("drop_traffic_pattern", "icmp_sweep")
        
        elif attack_type == "Botnet_C2":
            if source_ip and source_port:
                return ("block_connection", f"{source_ip}:{source_port}")
            elif source_ip:
                return ("block_ip", source_ip)
            return ("drop_traffic_pattern", "botnet_c2")
        
        else:  # Generic_Attack
            if source_ip:
                return ("block_ip", source_ip)
            return ("drop_traffic_pattern", "anomaly")
    
    @staticmethod
    def analyze_and_decide(
        result: dict,
        features: dict,
        source_ip: Optional[str] = None,
        source_port: Optional[str] = None,
    ) -> Optional[dict]:
        """
        Analyze attack and decide if blocking is needed.
        
        Returns:
            {
                "should_block": True/False,
                "attack_type": str,
                "confidence": float,
                "action": str,
                "target": str,
                "reason": str,
            }
            OR None if should not block
        """
        
        # Only proceed if ML model thinks it's an attack
        if not result.get("is_attack"):
            return None
        
        confidence = float(result.get("confidence", 0.5))
        
        # Classify attack type
        attack_type, type_confidence, analysis = AttackAnalyzer.classify_attack(features)
        
        # Decision threshold: needs both model confidence AND type confidence
        total_confidence = (confidence + type_confidence) / 2
        
        log.info(f"Attack detected: {attack_type} ({total_confidence:.2%})")
        log.info(f"  Analysis: {analysis.get('reason')}")
        
        # Threshold for blocking
        BLOCK_THRESHOLD = 0.70
        
        if total_confidence < BLOCK_THRESHOLD:
            log.warning(f"⚠️  Confidence too low ({total_confidence:.2%}) - not blocking")
            return None
        
        # Generate blocking action
        action, target = AttackAnalyzer.generate_blocking_action(
            attack_type,
            source_ip=source_ip,
            source_port=source_port
        )
        
        return {
            "should_block": True,
            "attack_type": attack_type,
            "confidence": round(total_confidence, 4),
            "action": action,
            "target": target,
            "reason": analysis.get("reason", "Detected attack"),
            "analysis": analysis,
        }


def extract_source_info(features: dict) -> Tuple[Optional[str], Optional[str]]:
    """Extract source IP and port if available from features."""
    # Note: Features don't contain IP/port directly
    # In real deployment, these would come from packet metadata
    return None, None


def should_block(result: dict, features: dict) -> Optional[dict]:
    """
    Quick helper to determine if an attack should be blocked.
    """
    analyzer = AttackAnalyzer()
    src_ip, src_port = extract_source_info(features)
    
    decision = analyzer.analyze_and_decide(
        result,
        features,
        source_ip=src_ip,
        source_port=src_port
    )
    
    return decision

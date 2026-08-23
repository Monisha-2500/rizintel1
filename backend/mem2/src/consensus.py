"""
Scanner Consensus Score Calculator

This is a KEY differentiator for the hackathon.
Shows how many scanners agree on each vulnerability.
"""
from typing import List, Dict
from src.models import NormalizedFinding


def calculate_scanner_consensus(findings: List[NormalizedFinding]) -> Dict:
    """
    Calculate how many scanners agree on a vulnerability
    
    Example: 
    findings from ZAP, Nuclei, OpenVAS -> 
    {
        "scanner_names": ["ZAP", "NUCLEI", "OPENVAS"],
        "detected_by_count": 3,
        "total_scanners": 3,
        "score": 1.0
    }
    """
    # Get unique scanner names
    scanner_names = list(set(f.scanner for f in findings))
    detected_by_count = len(scanner_names)
    
    # For now, assume we know total scanners (3: ZAP, Nuclei, OpenVAS)
    # In production, this would come from configuration
    TOTAL_SCANNERS = 3
    
    consensus_score = detected_by_count / TOTAL_SCANNERS
    
    return {
        "scanner_names": scanner_names,
        "detected_by_count": detected_by_count,
        "total_scanners": TOTAL_SCANNERS,
        "score": round(consensus_score, 2)
    }

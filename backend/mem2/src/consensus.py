"""
Scanner Consensus Score Calculator

This is a KEY differentiator for the hackathon.
Shows how many scanners agree on each vulnerability.
"""
from typing import List, Dict
try:
    from .models import NormalizedFinding
except (ImportError, ValueError):
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
    
    # Dynamically scale total_scanners if more scanners detected the finding
    TOTAL_SCANNERS = max(3, detected_by_count)
    
    consensus_score = min(1.0, detected_by_count / TOTAL_SCANNERS)
    
    return {
        "scanner_names": scanner_names,
        "detected_by_count": detected_by_count,
        "total_scanners": TOTAL_SCANNERS,
        "score": round(consensus_score, 2)
    }

"""
Simplified Fuzzy Matching for Vulnerability Names
"""
import re
from typing import Tuple, Dict, Set, Optional
from src.models import NormalizedFinding
from src.fingerprint import generate_fingerprint, generate_cve_fingerprint


def normalize_text(text: str) -> str:
    """Normalize text for better matching"""
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def extract_keywords(text: str) -> Set[str]:
    """Extract key vulnerability type words with synonyms"""
    text = normalize_text(text)
    
    # Common vulnerability name mappings (synonyms)
    vuln_mappings = {
        'sql': ['sql', 'sqli', 'sql injection'],
        'xss': ['xss', 'cross site scripting', 'cross-site scripting'],
        'rce': ['rce', 'remote code execution'],
        'path_traversal': ['path traversal', 'directory traversal', 'path'],
        'csrf': ['csrf', 'cross site request forgery'],
        'ssrf': ['ssrf', 'server side request forgery'],
        'idor': ['idor', 'insecure direct object reference'],
        'auth_bypass': ['auth bypass', 'authentication bypass'],
        'injection': ['injection', 'inject', 'sql injection'],
        'scripting': ['scripting', 'xss'],
        'disclosure': ['disclosure', 'exposure', 'info disclosure'],
        'header': ['header', 'headers'],
        'command': ['command', 'command injection', 'cmd'],
        'traversal': ['traversal', 'path traversal'],
    }
    
    result = set()
    text_lower = text.lower()
    
    # Check for vulnerability type mappings
    for category, variants in vuln_mappings.items():
        for variant in variants:
            if variant in text_lower:
                result.add(category)
                break
    
    # Also add individual words (length > 2)
    for word in text_lower.split():
        if len(word) > 2:
            result.add(word)
    
    return result

class VulnerabilityMatcher:
    def __init__(self, similarity_threshold: float = 0.60):
        self.threshold = similarity_threshold
    
    def exact_match(self, f1: NormalizedFinding, f2: NormalizedFinding) -> Tuple[bool, float]:
        """Exact fingerprint matching"""
        # CVE match (strongest)
        if f1.cve_id and f2.cve_id and f1.cve_id == f2.cve_id:
            return True, 1.0
        
        # Fingerprint match
        if generate_fingerprint(f1) == generate_fingerprint(f2):
            return True, 0.95
        
        return False, 0.0
    
    def fuzzy_match(self, f1: NormalizedFinding, f2: NormalizedFinding) -> Tuple[bool, float, Dict]:
        """Simple keyword-based fuzzy matching"""
        features = {
            "host_match": 1.0 if f1.host.lower() == f2.host.lower() else 0.0,
            "port_match": 1.0 if f1.port == f2.port else 0.0,
            "type_match": 1.0 if f1.vulnerability_type == f2.vulnerability_type else 0.0,
        }
        
        # Host must match
        if features["host_match"] == 0:
            return False, 0.0, features
        
        # Extract keywords from both names
        kw1 = extract_keywords(f1.vulnerability_name)
        kw2 = extract_keywords(f2.vulnerability_name)
        
        # Calculate keyword overlap
        if kw1 and kw2:
            common = len(kw1.intersection(kw2))
            total = len(kw1.union(kw2))
            keyword_score = common / total
        else:
            keyword_score = 0.0
        
        features["keyword_score"] = keyword_score
        
        # Also check if one name contains key parts of the other
        name1 = normalize_text(f1.vulnerability_name)
        name2 = normalize_text(f2.vulnerability_name)
        
        # Simple containment check
        containment_score = 0.0
        words1 = set(name1.split())
        words2 = set(name2.split())
        
        if words1 and words2:
            common_words = words1.intersection(words2)
            if common_words:
                containment_score = len(common_words) / max(len(words1), len(words2))
        
        features["containment_score"] = containment_score
        
        # Combined similarity (best of both)
        similarity = max(keyword_score, containment_score)
        features["similarity"] = similarity
        
        # Check if match
        is_match = similarity >= self.threshold
        
        return is_match, similarity, features
    
    def hybrid_match(self, f1: NormalizedFinding, f2: NormalizedFinding) -> Tuple[bool, float, Dict]:
        """Combine exact and fuzzy matching"""
        # Try exact first
        exact_match, exact_score = self.exact_match(f1, f2)
        if exact_match:
            features = {
                "cve_match": 1.0 if f1.cve_id and f2.cve_id and f1.cve_id == f2.cve_id else 0.0,
                "host_match": 1.0,
                "endpoint_similarity": 1.0,
                "parameter_match": 1.0,
                "vulnerability_similarity": 1.0
            }
            return True, 0.95, features
        
        # Try fuzzy
        fuzzy_match, fuzzy_score, features = self.fuzzy_match(f1, f2)
        if fuzzy_match:
            return True, fuzzy_score, features
        
        return False, 0.0, features
"""
Vulnerability Matcher — Asset-Aware Deduplication

Deduplication Decision Hierarchy:
  1. Asset boundary (HARD WALL — different assets → never a duplicate)
     - Known assets:  compare asset_id
     - UNMAPPED:      compare normalized host:port (instance boundary)
  2. Within the same asset:
     a. CVE exact match (strongest signal)
     b. Fingerprint exact match (host+endpoint+port+parameter+vuln_type)
     c. Fuzzy: vulnerability type + name keyword similarity

Cross-asset merging is explicitly PROHIBITED regardless of CVE, name, or
severity similarity. A finding on Asset A and the same CVE on Asset B
represent two separate remediation instances.
"""
import functools
import re
from typing import Tuple, Dict, Set, Optional, FrozenSet

try:
    from .models import NormalizedFinding
    from .fingerprint import generate_fingerprint, generate_cve_fingerprint
except (ImportError, ValueError):
    from src.models import NormalizedFinding
    from src.fingerprint import generate_fingerprint, generate_cve_fingerprint

@functools.lru_cache(maxsize=4096)
def normalize_text(text: str) -> str:
    """Normalize text for better matching"""
    if not text:
        return ""
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


NOISE_WORDS = {
    "vulnerability", "vulnerabilities", "finding", "findings", "detected", "found",
    "attack", "attacks", "issue", "issues", "via", "the", "and", "for", "with", "in",
    "on", "at", "to", "a", "an", "is", "of"
}

VULN_MAPPINGS = {
    'sql': ('sql', 'sqli', 'sql injection'),
    'xss': ('xss', 'cross site scripting', 'cross-site scripting'),
    'rce': ('rce', 'remote code execution'),
    'path_traversal': ('path traversal', 'directory traversal', 'path'),
    'csrf': ('csrf', 'cross site request forgery'),
    'ssrf': ('ssrf', 'server side request forgery'),
    'idor': ('idor', 'insecure direct object reference'),
    'auth_bypass': ('auth bypass', 'authentication bypass'),
    'injection': ('injection', 'inject', 'sql injection', 'sqli'),
    'scripting': ('scripting', 'xss'),
    'disclosure': ('disclosure', 'exposure', 'info disclosure'),
    'header': ('header', 'headers'),
    'command': ('command', 'command injection', 'cmd'),
    'traversal': ('traversal', 'path traversal', 'directory traversal'),
}


@functools.lru_cache(maxsize=4096)
def _extract_keywords_cached(text: str) -> FrozenSet[str]:
    """Internal cached keyword extraction returning immutable frozenset"""
    norm = normalize_text(text)
    if not norm:
        return frozenset()

    result = set()
    text_lower = norm.lower()

    for category, variants in VULN_MAPPINGS.items():
        for variant in variants:
            if variant in text_lower:
                result.add(category)
                break

    for word in text_lower.split():
        if len(word) > 2 and word not in NOISE_WORDS:
            result.add(word)

    return frozenset(result)


def extract_keywords(text: str) -> Set[str]:
    """Extract key vulnerability type words with synonyms"""
    return set(_extract_keywords_cached(text))


def _asset_boundary_str(finding: NormalizedFinding) -> str:
    """
    Canonical string representation of the asset boundary for a finding.

    Known asset: returns asset_id (e.g. 'ASSET-LAB-WEBGOAT').
    UNMAPPED:    returns 'UNMAPPED:host:port' (e.g. 'UNMAPPED:evil.host.net:8080').

    This is the single source of truth for the cross-asset hard wall.
    """
    asset_id = (finding.asset_id or "UNMAPPED").strip().upper()
    if asset_id == "UNMAPPED":
        host = finding.host.lower().strip()
        port = str(finding.port) if finding.port else "0"
        return f"UNMAPPED:{host}:{port}"
    return asset_id


def _same_asset_boundary(f1: NormalizedFinding, f2: NormalizedFinding) -> bool:
    """
    Returns True only if f1 and f2 are within the same asset boundary.
    This is the HARD WALL check that must be satisfied before any other
    similarity metric is evaluated.

    Two findings fail this check if:
    - They have different known asset_ids (e.g. ASSET-A vs ASSET-B)
    - They are UNMAPPED but on different host:port combinations
    - One is a known asset and the other is UNMAPPED

    If this returns False, the findings MUST NOT be merged.
    """
    return _asset_boundary_str(f1) == _asset_boundary_str(f2)


def _ports_compatible(p1: Optional[int], p2: Optional[int]) -> bool:
    """
    Check if ports are compatible for deduplication.
    If either port is missing/0, they are considered compatible.
    If both are present and differ, they represent different service instances.
    """
    if not p1 or not p2 or p1 == 0 or p2 == 0:
        return True
    return p1 == p2


def _normalize_endpoint(ep: Optional[str]) -> str:
    if not ep:
        return "/"
    ep = ep.strip().lower().rstrip("/")
    return ep if ep else "/"


def _endpoints_compatible(ep1: Optional[str], ep2: Optional[str]) -> bool:
    """
    Check if endpoints represent the same vulnerable component.
    - If either is root '/' or empty, assume compatible (scanner broad finding).
    - If normalized paths match, compatible.
    - If one path is a parent/child subpath of the same feature (e.g. /login vs /login/auth), compatible.
    - If completely different top-level components (e.g. /login vs /search), NOT compatible.
    """
    n1 = _normalize_endpoint(ep1)
    n2 = _normalize_endpoint(ep2)
    if n1 == "/" or n2 == "/":
        return True
    if n1 == n2:
        return True
    # Sub-path or prefix match
    if n1.startswith(n2 + "/") or n2.startswith(n1 + "/"):
        return True
    return False


def _parameters_compatible(param1: Optional[str], param2: Optional[str]) -> bool:
    """
    Check if vulnerable parameters are compatible.
    - If either parameter is None, empty, or 'none', compatible.
    - If both are provided, they must match (case-insensitive).
    """
    p1 = (param1 or "").strip().lower()
    p2 = (param2 or "").strip().lower()
    if not p1 or not p2 or p1 == "none" or p2 == "none":
        return True
    return p1 == p2


def compute_endpoint_similarity(ep1: Optional[str], ep2: Optional[str]) -> float:
    """Compute normalized similarity between two endpoints (0.0 to 1.0)."""
    n1 = _normalize_endpoint(ep1)
    n2 = _normalize_endpoint(ep2)
    if n1 == n2:
        return 1.0
    if n1 == "/" or n2 == "/":
        return 0.85
    if n1.startswith(n2 + "/") or n2.startswith(n1 + "/"):
        common_len = min(len(n1), len(n2))
        max_len = max(len(n1), len(n2))
        return round(0.70 + 0.25 * (common_len / max_len), 3)
    return 0.50


def compute_parameter_similarity(param1: Optional[str], param2: Optional[str]) -> float:
    """Compute similarity between two parameter names (0.0 to 1.0)."""
    p1 = (param1 or "").strip().lower()
    p2 = (param2 or "").strip().lower()
    if p1 == p2:
        return 1.0
    if not p1 or not p2 or p1 == "none" or p2 == "none":
        return 0.90
    return 0.0


class VulnerabilityMatcher:
    def __init__(self, similarity_threshold: float = 0.60):
        self.threshold = similarity_threshold

    def exact_match(self, f1: NormalizedFinding, f2: NormalizedFinding) -> Tuple[bool, float]:
        """
        Exact fingerprint or CVE matching — WITHIN the same asset only.
        Returns (is_match, score).
        """
        # HARD WALL: asset boundary must match before any other check
        if not _same_asset_boundary(f1, f2):
            return False, 0.0

        # Port/Service Instance boundary check: different ports represent different service instances
        if not _ports_compatible(f1.port, f2.port):
            return False, 0.0

        # Endpoint/Component Instance check: distinct endpoints represent distinct instances
        if not _endpoints_compatible(f1.endpoint, f2.endpoint):
            return False, 0.0

        # Parameter check: distinct parameter targets represent distinct instances
        if not _parameters_compatible(f1.parameter, f2.parameter):
            return False, 0.0

        # CVE match (strongest within-asset signal)
        if f1.cve_id and f2.cve_id and f1.cve_id == f2.cve_id:
            return True, 1.0

        # Fingerprint match (host+endpoint+port+parameter+vuln_type within same asset)
        if generate_fingerprint(f1) == generate_fingerprint(f2):
            return True, 0.95

        return False, 0.0

    def fuzzy_match(self, f1: NormalizedFinding, f2: NormalizedFinding) -> Tuple[bool, float, Dict]:
        """
        Keyword & containment fuzzy matching — WITHIN the same asset only.
        Returns (is_match, similarity_score, features).
        """
        endpoint_sim = compute_endpoint_similarity(f1.endpoint, f2.endpoint)
        param_sim = compute_parameter_similarity(f1.parameter, f2.parameter)
        same_asset = _same_asset_boundary(f1, f2)
        ports_compat = _ports_compatible(f1.port, f2.port)
        endpoints_compat = _endpoints_compatible(f1.endpoint, f2.endpoint)

        type_match = 1.0 if (f1.vulnerability_type == f2.vulnerability_type and f1.vulnerability_type not in {"OTHER", "GENERIC"}) else 0.0

        features = {
            "asset_boundary_match": 1.0 if same_asset else 0.0,
            "host_match": 1.0 if f1.host.lower() == f2.host.lower() else 0.0,
            "port_match": 1.0 if ports_compat else 0.0,
            "endpoint_match": 1.0 if endpoints_compat else 0.0,
            "endpoint_similarity": endpoint_sim,
            "parameter_match": param_sim,
            "type_match": type_match,
            "cve_match": 0.0,
            "vulnerability_similarity": 0.0,
            "match_method": "HYBRID",
        }

        # HARD WALL: asset boundary, ports, endpoints must match
        if not same_asset or not ports_compat or not endpoints_compat:
            features["similarity"] = 0.0
            return False, 0.0, features

        # If both have CVEs and they are different, they are different CVEs -> do not fuzzy merge
        if f1.cve_id and f2.cve_id and f1.cve_id != f2.cve_id:
            features["similarity"] = 0.0
            return False, 0.0, features

        # Extract keywords from both names
        kw1 = extract_keywords(f1.vulnerability_name)
        kw2 = extract_keywords(f2.vulnerability_name)

        if kw1 and kw2:
            common = len(kw1.intersection(kw2))
            total = len(kw1.union(kw2))
            keyword_score = common / total
        else:
            keyword_score = 0.0

        features["keyword_score"] = keyword_score

        name1 = normalize_text(f1.vulnerability_name)
        name2 = normalize_text(f2.vulnerability_name)

        containment_score = 0.0
        words1 = set(name1.split())
        words2 = set(name2.split())

        if words1 and words2:
            common_words = words1.intersection(words2)
            if common_words:
                containment_score = len(common_words) / max(len(words1), len(words2))

        features["containment_score"] = containment_score

        kw_sim = max(keyword_score, containment_score)
        # If standardized vulnerability type matches, incorporate it
        if type_match == 1.0:
            vuln_similarity = max(kw_sim, 0.40 * type_match + 0.60 * kw_sim)
        else:
            vuln_similarity = kw_sim

        features["similarity"] = vuln_similarity
        features["vulnerability_similarity"] = round(vuln_similarity, 3)

        is_match = vuln_similarity >= self.threshold
        if is_match:
            # Composite match confidence score based on vuln similarity, endpoint, and param
            match_score = round(0.50 * vuln_similarity + 0.30 * endpoint_sim + 0.20 * param_sim, 3)
            return True, match_score, features

        return False, 0.0, features

    def hybrid_match(self, f1: NormalizedFinding, f2: NormalizedFinding) -> Tuple[bool, float, Dict]:
        """
        Combine exact and fuzzy matching — asset boundary enforced at every level.

        Returns (is_match, score, features) where features contains:
          - cve_match (0.0 or 1.0)
          - host_match (1.0)
          - endpoint_similarity (float 0.0-1.0)
          - parameter_match (float 0.0-1.0)
          - vulnerability_similarity (float 0.0-1.0)
          - match_method ("EXACT_CVE" | "EXACT_FINGERPRINT" | "HYBRID")
        """
        # Fast-reject: asset boundary mismatch
        if not _same_asset_boundary(f1, f2):
            return False, 0.0, {"asset_boundary_match": 0.0, "match_method": "NONE"}

        endpoint_sim = compute_endpoint_similarity(f1.endpoint, f2.endpoint)
        param_sim = compute_parameter_similarity(f1.parameter, f2.parameter)

        # 1. Exact CVE match
        if (
            f1.cve_id and f2.cve_id and f1.cve_id == f2.cve_id
            and _ports_compatible(f1.port, f2.port)
            and _endpoints_compatible(f1.endpoint, f2.endpoint)
            and _parameters_compatible(f1.parameter, f2.parameter)
        ):
            features = {
                "asset_boundary_match": 1.0,
                "cve_match": 1.0,
                "host_match": 1.0 if f1.host.lower() == f2.host.lower() else 0.0,
                "endpoint_similarity": endpoint_sim,
                "parameter_match": param_sim,
                "vulnerability_similarity": 1.0,
                "match_method": "EXACT_CVE"
            }
            return True, 1.0, features

        # 2. Exact Fingerprint match
        if (
            generate_fingerprint(f1) == generate_fingerprint(f2)
            and _ports_compatible(f1.port, f2.port)
            and _endpoints_compatible(f1.endpoint, f2.endpoint)
            and _parameters_compatible(f1.parameter, f2.parameter)
        ):
            cve_m = 1.0 if (f1.cve_id and f2.cve_id and f1.cve_id == f2.cve_id) else 0.0
            features = {
                "asset_boundary_match": 1.0,
                "cve_match": cve_m,
                "host_match": 1.0 if f1.host.lower() == f2.host.lower() else 0.0,
                "endpoint_similarity": 1.0,
                "parameter_match": 1.0,
                "vulnerability_similarity": 1.0,
                "match_method": "EXACT_FINGERPRINT"
            }
            return True, 0.95, features

        # 3. Fuzzy / Hybrid match
        fuzzy_match, fuzzy_score, features = self.fuzzy_match(f1, f2)
        if fuzzy_match:
            return True, fuzzy_score, features

        return False, 0.0, features
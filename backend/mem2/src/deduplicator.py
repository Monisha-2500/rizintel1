"""
Main Deduplication Engine - Orchestrates everything
"""
from typing import List, Dict, Set, Tuple, Optional, Any
import uuid
try:
    from .models import NormalizedFinding, DeduplicatedFinding, DeduplicationMetrics
    from .fingerprint import generate_fingerprint
    from .matcher import (
        VulnerabilityMatcher,
        _asset_boundary_str,
        _ports_compatible,
        _endpoints_compatible,
        _parameters_compatible,
        extract_keywords,
        normalize_text,
        NOISE_WORDS,
    )
    from .consensus import calculate_scanner_consensus
except (ImportError, ValueError):
    from src.models import NormalizedFinding, DeduplicatedFinding, DeduplicationMetrics
    from src.fingerprint import generate_fingerprint
    from src.matcher import (
        VulnerabilityMatcher,
        _asset_boundary_str,
        _ports_compatible,
        _endpoints_compatible,
        _parameters_compatible,
        extract_keywords,
        normalize_text,
        NOISE_WORDS,
    )
    from src.consensus import calculate_scanner_consensus


class Deduplicator:
    def __init__(self, similarity_threshold: float = 0.60):
        """
        Initialize the deduplication engine
        
        Args:
            similarity_threshold: 0.0 to 1.0, minimum similarity for fuzzy matching
        """
        self.matcher = VulnerabilityMatcher(similarity_threshold)
    
    def deduplicate(self, findings: List[NormalizedFinding]) -> Dict:
        """
        Main entry point - deduplicate findings and return results
        
        Args:
            findings: List of normalized findings from Member 1
            
        Returns:
            Dictionary with:
            - schema_version: "1.0"
            - findings: List of DeduplicatedFinding objects
            - deduplication_metrics: DeduplicationMetrics object
        """
        # Step 1: Group by fingerprint (fast exact matching)
        fingerprint_groups = self._group_by_fingerprint(findings)
        
        # Step 2: Merge groups using fuzzy matching
        merged_groups = self._merge_similar_groups(fingerprint_groups)
        
        # Step 3: Create deduplicated findings
        unique_findings = []
        for group in merged_groups:
            deduped = self._create_deduplicated_finding(group)
            unique_findings.append(deduped)
        
        # Step 4: Calculate metrics
        metrics = self._calculate_metrics(findings, unique_findings)

        def _dump(obj):
            if hasattr(obj, "model_dump"):
                return obj.model_dump()
            return obj.dict()

        return {
            "schema_version": "1.0",
            "findings": [_dump(f) for f in unique_findings],
            "deduplication_metrics": _dump(metrics)
        }
    
    def _group_by_fingerprint(self, findings: List[NormalizedFinding]) -> List[List[NormalizedFinding]]:
        """Group findings with identical fingerprints"""
        groups = {}
        for finding in findings:
            fp = generate_fingerprint(finding)
            if fp not in groups:
                groups[fp] = []
            groups[fp].append(finding)
        return list(groups.values())
    
    def _merge_similar_groups(self, groups: List[List[NormalizedFinding]]) -> List[List[NormalizedFinding]]:
        """
        Merge groups using asset-partitioned blocking, candidate indexing, and fuzzy matching.
        Preserves 100% of matching semantics while eliminating cross-asset and disjoint comparisons.
        """
        # 1. Partition groups by asset boundary (Hard Wall: cross-asset matching is impossible)
        asset_partitions: Dict[str, List[List[NormalizedFinding]]] = {}
        for group in groups:
            if not group:
                continue
            asset_key = _asset_boundary_str(group[0])
            if asset_key not in asset_partitions:
                asset_partitions[asset_key] = []
            asset_partitions[asset_key].append(group)

        merged: List[List[NormalizedFinding]] = []

        # Helper to extract candidate blocking keys
        def _get_keys(grp: List[NormalizedFinding]) -> Set[str]:
            keys = set()
            for f in grp:
                if f.cve_id:
                    keys.add(f"cve:{f.cve_id.strip().upper()}")
                v_type = (f.vulnerability_type or "").strip().upper()
                if v_type and v_type not in {"OTHER", "GENERIC"}:
                    keys.add(f"type:{v_type}")
                for kw in extract_keywords(f.vulnerability_name or ""):
                    keys.add(f"kw:{kw}")
                norm_words = normalize_text(f.vulnerability_name or "").split()
                for w in norm_words:
                    if len(w) > 2 and w not in NOISE_WORDS:
                        keys.add(f"word:{w}")
            if not keys:
                keys.add("wildcard:ALL")
            return keys

        # 2. Perform deduplication strictly within each asset partition
        for asset_key, partition_groups in asset_partitions.items():
            n_grp = len(partition_groups)
            if n_grp == 1:
                merged.append(partition_groups[0].copy())
                continue

            # Build inverted index for fast candidate retrieval within asset partition
            group_keys_list = [_get_keys(grp) for grp in partition_groups]
            key_to_indices: Dict[str, List[int]] = {}
            for idx, k_set in enumerate(group_keys_list):
                for k in k_set:
                    if k not in key_to_indices:
                        key_to_indices[k] = []
                    key_to_indices[k].append(idx)

            used = set()
            for i, group1 in enumerate(partition_groups):
                if i in used:
                    continue

                current_group = group1.copy()
                used.add(i)

                # Find candidate indices sharing at least one blocking key
                current_keys = _get_keys(current_group)
                candidate_set: Set[int] = set()
                for k in current_keys:
                    for j in key_to_indices.get(k, []):
                        if j > i and j not in used:
                            candidate_set.add(j)

                # Also include wildcard if any group had empty keys
                for j in key_to_indices.get("wildcard:ALL", []):
                    if j > i and j not in used:
                        candidate_set.add(j)

                for j in sorted(candidate_set):
                    if j in used:
                        continue

                    group2 = partition_groups[j]

                    # Fast-path 1: Representative comparison
                    is_match, score, _ = self.matcher.hybrid_match(current_group[0], group2[0])
                    if is_match:
                        current_group.extend(group2)
                        used.add(j)
                        continue

                    # Fast-path 2: Multi-member Cartesian product if representative failed
                    if len(current_group) > 1 or len(group2) > 1:
                        match_found = False
                        for f1 in current_group:
                            for f2 in group2:
                                is_m, _, _ = self.matcher.hybrid_match(f1, f2)
                                if is_m:
                                    match_found = True
                                    break
                            if match_found:
                                break

                        if match_found:
                            current_group.extend(group2)
                            used.add(j)

                merged.append(current_group)

        return merged
    
    def _create_deduplicated_finding(self, group: List[NormalizedFinding]) -> DeduplicatedFinding:
        """Create a DeduplicatedFinding from a group of matching findings"""
        # Find best representative (prioritize findings with CVE and resolved asset_id)
        representative = max(
            group,
            key=lambda f: (
                1 if f.cve_id else 0,
                1 if (f.asset_id and f.asset_id.upper() != "UNMAPPED") else 0,
                len(f.description or "")
            )
        )
        
        # Calculate scanner consensus (INDEPENDENT signal: how many distinct scanners detected this)
        consensus = calculate_scanner_consensus(group)
        
        # Build source findings preserving full provenance
        source_findings = [
            {
                "finding_id": f.finding_id,
                "scanner": f.scanner,
                "evidence": f.evidence or "No evidence provided"
            }
            for f in group
        ]
        
        # Compute real match_score, match_method, and match_features independently from consensus
        if len(group) == 1:
            # Singleton finding: single finding with 100% self-consistency
            f = group[0]
            match_method = "SINGLETON"
            match_score = 1.0
            match_features = {
                "cve_match": 1.0 if f.cve_id else 0.0,
                "host_match": 1.0,
                "endpoint_similarity": 1.0,
                "parameter_match": 1.0,
                "vulnerability_similarity": 1.0
            }
        else:
            # Multi-finding group: evaluate pairwise matches against the representative
            pairwise_scores = []
            pairwise_features = []
            methods = []
            
            for f in group:
                if f.finding_id == representative.finding_id:
                    continue
                is_match, score, features = self.matcher.hybrid_match(representative, f)
                if not is_match:
                    # Fallback: check if f matched any other member in the group
                    for other in group:
                        if other.finding_id != f.finding_id:
                            is_match, score, features = self.matcher.hybrid_match(other, f)
                            if is_match:
                                break
                
                pairwise_scores.append(score if is_match else 0.60)
                pairwise_features.append(features if is_match else {})
                methods.append(features.get("match_method", "HYBRID") if is_match else "HYBRID")

            # Deterministic group aggregation: arithmetic mean of pairwise match scores
            match_score = round(sum(pairwise_scores) / len(pairwise_scores), 3) if pairwise_scores else 1.0

            # Determine dominant match method
            if all(m == "EXACT_CVE" for m in methods):
                match_method = "EXACT_CVE"
            elif all(m in {"EXACT_CVE", "EXACT_FINGERPRINT"} for m in methods):
                match_method = "EXACT_FINGERPRINT"
            else:
                match_method = "HYBRID"

            # Aggregate real match features across pairwise comparisons
            def _avg_feat(key: str, default_val: float = 1.0) -> float:
                vals = [pf.get(key) for pf in pairwise_features if pf.get(key) is not None]
                return round(sum(vals) / len(vals), 3) if vals else default_val

            match_features = {
                "cve_match": _avg_feat("cve_match", 1.0 if representative.cve_id else 0.0),
                "host_match": _avg_feat("host_match", 1.0),
                "endpoint_similarity": _avg_feat("endpoint_similarity", 1.0),
                "parameter_match": _avg_feat("parameter_match", 1.0),
                "vulnerability_similarity": _avg_feat("vulnerability_similarity", 1.0)
            }

        # Create deduplication info
        dedup_info = {
            "duplicate_count": len(group),
            "merged_finding_ids": [f.finding_id for f in group],
            "match_method": match_method,
            "match_score": match_score,
            "match_features": match_features
        }
        
        # Create asset dict
        asset = {
            "asset_id": representative.asset_id,
            "host": representative.host,
            "endpoint": representative.endpoint,
            "port": representative.port,
            "parameter": representative.parameter
        }
        
        # Find timestamps
        timestamps = [f.timestamp for f in group]
        first_seen = min(timestamps)
        last_seen = max(timestamps)
        
        # Generate unique ID
        finding_id = f"DEDUP-{str(uuid.uuid4())[:8].upper()}"
        
        return DeduplicatedFinding(
            finding_id=finding_id,
            cve_id=representative.cve_id,
            vulnerability_name=representative.vulnerability_name,
            vulnerability_type=representative.vulnerability_type,
            severity=representative.severity,
            asset=asset,
            deduplication=dedup_info,
            scanner_consensus=consensus,
            source_findings=source_findings,
            first_seen=first_seen,
            last_seen=last_seen
        )
    
    def _calculate_metrics(self, raw: List[NormalizedFinding], unique: List[DeduplicatedFinding]) -> DeduplicationMetrics:
        """Calculate deduplication metrics for dashboard"""
        total_raw = len(raw)
        unique_count = len(unique)
        
        # Count scanners
        scanner_counts = {}
        for f in raw:
            scanner_counts[f.scanner] = scanner_counts.get(f.scanner, 0) + 1
        
        return DeduplicationMetrics(
            total_raw_findings=total_raw,
            unique_findings=unique_count,
            duplicates_removed=total_raw - unique_count,
            duplicate_reduction_rate=(total_raw - unique_count) / total_raw if total_raw > 0 else 0,
            scanner_breakdown=scanner_counts
        )

"""
Main Deduplication Engine - Orchestrates everything
"""
from typing import List, Dict
import uuid
from src.models import NormalizedFinding, DeduplicatedFinding, DeduplicationMetrics
from src.fingerprint import generate_fingerprint
from src.matcher import VulnerabilityMatcher
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
        
        return {
            "schema_version": "1.0",
            "findings": [f.dict() for f in unique_findings],
            "deduplication_metrics": metrics.dict()
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
        """Merge groups using fuzzy matching"""
        merged = []
        used = set()
        
        for i, group1 in enumerate(groups):
            if i in used:
                continue
            
            current_group = group1.copy()
            used.add(i)
            
            for j, group2 in enumerate(groups):
                if j <= i or j in used:
                    continue
                
                # Check if any finding from group1 matches any from group2
                match_found = False
                for f1 in group1:
                    for f2 in group2:
                        is_match, score, _ = self.matcher.hybrid_match(f1, f2)
                        if is_match:
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
        # Find best representative (prioritize findings with CVE)
        representative = max(group, key=lambda f: 1 if f.cve_id else 0)
        
        # Calculate scanner consensus
        consensus = calculate_scanner_consensus(group)
        
        # Build source findings
        source_findings = [
            {
                "finding_id": f.finding_id,
                "scanner": f.scanner,
                "evidence": f.evidence or "No evidence provided"
            }
            for f in group
        ]
        
        # Create deduplication info
        dedup_info = {
            "duplicate_count": len(group),
            "merged_finding_ids": [f.finding_id for f in group],
            "match_method": "HYBRID",
            "match_score": consensus["score"],
            "match_features": {
                "cve_match": 1.0 if all(f.cve_id for f in group) else 0.0,
                "host_match": 1.0,
                "endpoint_similarity": 1.0,
                "parameter_match": 1.0,
                "vulnerability_similarity": 1.0
            }
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

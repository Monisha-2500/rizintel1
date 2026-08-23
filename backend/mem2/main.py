"""
Member 2 - Deduplication Engine Entry Point
"""
import json
from src.models import NormalizedFinding
from src.deduplicator import Deduplicator


def load_sample_data():
    """Load sample input from Member 1"""
    with open('data/sample_input.json', 'r') as f:
        data = json.load(f)
    
    # Validate and parse
    findings = [NormalizedFinding(**f) for f in data['findings']]
    return findings


def main():
    print("🔄 MEMBER 2 - DEDUPLICATION ENGINE")
    print("=" * 50)
    
    # Load input
    print("📥 Loading findings from Member 1...")
    findings = load_sample_data()
    print(f"✅ Loaded {len(findings)} findings from scanners")
    
    # Run deduplication
    print("\n🔍 Running deduplication...")
    deduplicator = Deduplicator(similarity_threshold=0.60)
    result = deduplicator.deduplicate(findings)
    
    # Print results
    metrics = result['deduplication_metrics']
    print(f"\n📊 DEDUPLICATION RESULTS:")
    print(f"   Raw findings: {metrics['total_raw_findings']}")
    print(f"   Unique findings: {metrics['unique_findings']}")
    print(f"   Duplicates removed: {metrics['duplicates_removed']}")
    print(f"   Reduction rate: {metrics['duplicate_reduction_rate']:.1%}")
    
    print(f"\n🔬 SCANNER CONSENSUS:")
    for finding in result['findings']:
        consensus = finding['scanner_consensus']
        print(f"   {finding['vulnerability_name']}: {consensus['detected_by_count']}/{consensus['total_scanners']} scanners")
    
    # Save output
    with open('output.json', 'w') as f:
        json.dump(result, f, indent=2)
    print("\n✅ Output saved to output.json")
    
    return result


if __name__ == "__main__":
    main()

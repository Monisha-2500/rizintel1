"""Main execution script for Module M5 — Asset Context + Dynamic Risk Scoring Engine.

Demonstrates:
1. Loading and evaluating contract-compliant input (`sample_input.json`).
2. Handling valid findings with missing CVE (`missing_cve_input.json`).
3. Validating standalone asset context (`asset_context.json`).
4. Rejection and error reporting on invalid inputs (`malformed_input.json`).
5. Running the end-to-end Risk Engine pipeline with transparent score breakdowns and drivers.
"""

import json
from pathlib import Path
from pydantic import ValidationError

from src.models import AssetContext, M5RiskEngineOutput
from src.risk_engine import RiskEngine


def load_json_file(file_path: Path) -> dict:
    """Load JSON content from a given file path."""
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def main():
    base_dir = Path(__file__).parent
    input_dir = base_dir / "input"

    engine = RiskEngine()

    print("=" * 75)
    print("Module M5: Deterministic Rule-Based Risk Scoring Engine (Contract v1.0)")
    print("=" * 75)

    # -------------------------------------------------------------------------
    # Test 1: Sample Input (Valid High/Critical Finding)
    # -------------------------------------------------------------------------
    sample_file = input_dir / "sample_input.json"
    print(f"\n[1] Evaluating Sample Input: {sample_file.name}")
    try:
        sample_data = load_json_file(sample_file)
        result: M5RiskEngineOutput = engine.assess_finding(sample_data)
        assessment = result.risk_assessment
        print("  [PASS] Validation: SUCCESS")
        print(f"  [+] Finding ID:      {result.finding_id}")
        print(f"  [+] CVE ID:          {result.cve_id}")
        print(f"  [+] Vulnerability:   {result.vulnerability_name}")
        print(f"  [+] Final Risk Score: {assessment.risk_score} / 100.0")
        print(f"  [+] Risk Level:      {assessment.risk_level}")
        print(f"  [+] Scoring Version: {assessment.scoring_version}")
        print(f"  [+] Risk Drivers:    {assessment.risk_drivers}")
        print("  [+] Score Breakdown:")
        breakdown_dict = assessment.score_breakdown.model_dump()
        for factor, details in breakdown_dict.items():
            print(f"      - {factor:20s}: input = {str(details['input']):<10s} -> points = {details['points']}")
    except ValidationError as e:
        print(f"  [FAIL] Validation FAILED: {e}")

    # -------------------------------------------------------------------------
    # Test 2: Missing CVE Input (Valid finding without CVE)
    # -------------------------------------------------------------------------
    missing_cve_file = input_dir / "missing_cve_input.json"
    print(f"\n[2] Evaluating Missing CVE Input: {missing_cve_file.name}")
    try:
        missing_cve_data = load_json_file(missing_cve_file)
        result: M5RiskEngineOutput = engine.assess_finding(missing_cve_data)
        assessment = result.risk_assessment
        print("  [PASS] Validation: SUCCESS (null cve_id handled gracefully)")
        print(f"  [+] Finding ID:      {result.finding_id}")
        print(f"  [+] CVE ID:          {result.cve_id}")
        print(f"  [+] Vulnerability:   {result.vulnerability_name}")
        print(f"  [+] Final Risk Score: {assessment.risk_score} / 100.0")
        print(f"  [+] Risk Level:      {assessment.risk_level}")
        print(f"  [+] Risk Drivers:    {assessment.risk_drivers}")
        print("  [+] Score Breakdown:")
        breakdown_dict = assessment.score_breakdown.model_dump()
        for factor, details in breakdown_dict.items():
            print(f"      - {factor:20s}: input = {str(details['input']):<10s} -> points = {details['points']}")
    except ValidationError as e:
        print(f"  [FAIL] Validation FAILED: {e}")

    # -------------------------------------------------------------------------
    # Test 3: Standalone Asset Context Validation
    # -------------------------------------------------------------------------
    asset_context_file = input_dir / "asset_context.json"
    print(f"\n[3] Testing Standalone Asset Context: {asset_context_file.name}")
    try:
        asset_data = load_json_file(asset_context_file)
        validated_asset = AssetContext.model_validate(asset_data)
        print("  [PASS] Validation: SUCCESS")
        print(f"  [+] Asset ID:          {validated_asset.asset_id} ({validated_asset.asset_name})")
        print(f"  [+] Environment:       {validated_asset.environment} | Criticality: {validated_asset.asset_criticality}")
        print(f"  [+] Internet Exposure: {validated_asset.internet_exposure} (boolean)")
    except ValidationError as e:
        print(f"  [FAIL] Validation FAILED: {e}")

    # -------------------------------------------------------------------------
    # Test 4: Malformed Input (Intentionally Invalid Ranges / Types)
    # -------------------------------------------------------------------------
    malformed_file = input_dir / "malformed_input.json"
    print(f"\n[4] Testing Malformed Input (Expected Validation Failures): {malformed_file.name}")
    try:
        malformed_data = load_json_file(malformed_file)
        engine.assess_finding(malformed_data)
        print("  [FAIL] UNEXPECTED: Malformed input passed validation!")
    except ValidationError as e:
        print("  [PASS] Validation: Correctly REJECTED malformed input.")
        print(f"  [+] Caught {len(e.errors())} schema violation(s):")
        for err in e.errors():
            loc = " -> ".join(str(p) for p in err["loc"])
            print(f"     - Field '{loc}': {err['msg']}")

    print("\n" + "=" * 75)
    print("M5 Deterministic Rule-Based Risk Scoring Pipeline Execution Complete.")
    print("=" * 75)


if __name__ == "__main__":
    main()

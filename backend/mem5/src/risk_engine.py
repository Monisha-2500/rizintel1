"""Core Risk Engine Pipeline for Module M5 — Asset Context + Dynamic Risk Scoring.

RESPONSIBILITY:
Orchestrates the complete risk assessment pipeline:
  [1] Input Ingestion & Invariant Validation
  [2] Dynamic Rule-Based Risk Scoring Evaluation
  [3] Categorical Risk Level Classification
  [4] Score Breakdown & Risk Driver Synthesis
  [5] Contract-Compliant Output Synthesis (M5 -> M6)

Strictly adheres to Interface Contract v1.0.
"""

from datetime import datetime, timezone
from typing import Dict, Any, Union

from .models import (
    M5RiskEngineInput,
    M5RiskEngineOutput,
    RiskAssessment,
    AssessmentMetadata,
    ScannerConsensus,
    FindingConfidence,
)
from .scoring import RiskScoringEngine
from .classifier import RiskClassifier
from .explanation import RiskExplanationGenerator


class RiskEngine:
    """End-to-end Risk Engine coordinating input validation through output assessment."""

    def __init__(
        self,
        scoring_engine: RiskScoringEngine = None,
        classifier: RiskClassifier = None,
        explanation_generator: RiskExplanationGenerator = None,
    ):
        self.scoring_engine = scoring_engine or RiskScoringEngine()
        self.classifier = classifier or RiskClassifier()
        self.explanation_generator = explanation_generator or RiskExplanationGenerator()
        self.engine_version = "1.0.0"

    def assess_finding(self, raw_input: Union[Dict[str, Any], M5RiskEngineInput]) -> M5RiskEngineOutput:
        """Execute the end-to-end risk assessment pipeline.

        Pipeline Stages:
          Step 1: Input Ingestion & Pydantic Validation
          Step 2: Rule-Based Scoring Policy Evaluation
          Step 3: Categorical Risk Level Classification
          Step 4: Transparent Score Breakdown & Risk Driver Generation
          Step 5: Contract-Compliant Output Packaging (M5 -> M6)

        Args:
            raw_input: Raw JSON dictionary or pre-parsed M5RiskEngineInput.

        Returns:
            M5RiskEngineOutput: Fully structured and validated output according to contract v1.0.
        """
        # ====================================================================
        # Step 1: Input Ingestion & Validation
        # ====================================================================
        if isinstance(raw_input, dict):
            validated_input: M5RiskEngineInput = M5RiskEngineInput.model_validate(raw_input)
        elif isinstance(raw_input, M5RiskEngineInput):
            validated_input = raw_input
        else:
            raise TypeError(f"Invalid input type: {type(raw_input)}. Expected dict or M5RiskEngineInput.")

        # ====================================================================
        # Step 2: Scoring Policy Evaluation
        # ====================================================================
        # Computes deterministic additive score bounded to [0.0, 100.0] and structured breakdown
        raw_score, score_breakdown = self.scoring_engine.compute_score(validated_input)

        # ====================================================================
        # Step 3: Classification
        # ====================================================================
        # Maps numerical score to canonical risk level (LOW, MEDIUM, HIGH, CRITICAL)
        risk_level = self.classifier.classify(raw_score)

        # ====================================================================
        # Step 4: Risk Drivers & Explanations
        # ====================================================================
        # Identifies triggered risk drivers
        risk_drivers = self.explanation_generator.generate_drivers(validated_input)

        # ====================================================================
        # Step 5: Risk Assessment Output Packaging (M5 -> M6 Contract)
        # ====================================================================
        risk_assessment = RiskAssessment(
            risk_score=raw_score,
            risk_level=risk_level,
            score_breakdown=score_breakdown,
            risk_drivers=risk_drivers,
            scoring_version=self.scoring_engine.scoring_version
        )

        metadata = AssessmentMetadata(
            engine_name="M5_Risk_Engine",
            engine_version=self.engine_version,
            assessed_at=datetime.now(timezone.utc).isoformat(),
            status="SUCCESS",
            notes="Evaluated by Module M5 Deterministic Rule-Based Scoring Engine."
        )

        output = M5RiskEngineOutput(
            schema_version="1.0",
            scoring_version=self.scoring_engine.scoring_version,
            finding_id=validated_input.finding_id,
            cve_id=validated_input.cve_id,
            vulnerability_name=validated_input.vulnerability_name,
            scanner_consensus=ScannerConsensus(
                scanner_sources=validated_input.scanner_sources,
                scanner_consensus_score=validated_input.scanner_consensus_score
            ),
            finding_confidence=FindingConfidence(
                finding_confidence_score=validated_input.finding_confidence_score,
                finding_confidence_classification=validated_input.finding_confidence_classification
            ),
            threat_intelligence=validated_input.threat_intelligence,
            asset_context=validated_input.asset_context,
            risk_assessment=risk_assessment,
            metadata=metadata
        )

        return output

"""
pipeline.py
-----------
The orchestrator. This is the piece you demo: it doesn't know or care that
"ZAP", "Nuclei", "OpenVAS" specifically exist — it just asks the registry
for whichever adapter matches the requested scanner name and runs it.

Scanner Output -> Parser -> Validation (built into StandardFinding via pydantic)
-> Standardized Finding Object
"""

from typing import List
import scanner_adapters  # triggers auto-registration of all adapters
from scanner_adapters.base import get_registered_adapters
from schema import StandardFinding


class NormalizationPipeline:
    def __init__(self):
        self.adapters = get_registered_adapters()

    def available_scanners(self) -> List[str]:
        return list(self.adapters.keys())

    def normalize(self, scanner_name: str, raw_data: str) -> List[StandardFinding]:
        adapter_cls = self.adapters.get(scanner_name)
        if adapter_cls is None:
            raise ValueError(
                f"No adapter registered for scanner '{scanner_name}'. "
                f"Available: {self.available_scanners()}"
            )
        adapter = adapter_cls()
        return adapter.parse(raw_data)

    def normalize_batch(self, sources: dict) -> List[StandardFinding]:
        """
        sources: { "ZAP": raw_zap_string, "Nuclei": raw_nuclei_string, ... }
        Returns one merged, flat list of StandardFinding across all scanners.
        """
        all_findings = []
        for scanner_name, raw_data in sources.items():
            try:
                findings = self.normalize(scanner_name, raw_data)
                print(f"[Pipeline] {scanner_name}: normalized {len(findings)} findings")
                all_findings.extend(findings)
            except Exception as e:
                print(f"[Pipeline] Failed to process {scanner_name}: {e}")
        return all_findings

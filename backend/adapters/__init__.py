"""
adapters package
================
Provides boundary adapters between M1-M7 modules ensuring strict conformance
to the frozen RizIntel Schema v1.0 interface contract.
"""

from .m1_adapter import M1NormalizedFindingAdapter
from .m5_adapter import M5RiskEngineAdapter
from .m7_adapter import M7ActionableFindingAdapter

__all__ = [
    "M1NormalizedFindingAdapter",
    "M5RiskEngineAdapter",
    "M7ActionableFindingAdapter",
]

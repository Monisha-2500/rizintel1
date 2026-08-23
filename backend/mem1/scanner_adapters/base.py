"""
base.py
-------
Defines the contract every scanner adapter must follow, plus a registry
that auto-discovers adapters. THIS is the piece that makes the architecture
"plug-in" instead of hardcoded: main.py never imports zap.py/nuclei.py by name.
It just asks the registry "who can handle this file?" and loops over whoever
registered themselves.

To add a new scanner tomorrow (e.g. Nessus):
1. Create scanner_adapters/nessus.py
2. Subclass BaseAdapter, implement parse()
3. Add the one line: @register_adapter("Nessus") above the class
4. Done — nothing else in the codebase changes.
"""

from abc import ABC, abstractmethod
from typing import List
from schema import StandardFinding

_ADAPTER_REGISTRY = {}


def register_adapter(scanner_name: str):
    """Class decorator. Registers an adapter under a scanner name."""
    def wrapper(cls):
        _ADAPTER_REGISTRY[scanner_name] = cls
        return cls
    return wrapper


def get_registered_adapters() -> dict:
    return dict(_ADAPTER_REGISTRY)


class BaseAdapter(ABC):
    """Every scanner adapter implements parse(raw_data) -> List[StandardFinding]."""

    scanner_name: str = "UNKNOWN"

    @abstractmethod
    def parse(self, raw_data: str) -> List[StandardFinding]:
        """
        raw_data: the raw file content (JSON string or XML string) from the scanner.
        Returns a list of validated StandardFinding objects.
        Should NOT raise on a single bad record — log/skip it and keep going,
        so one malformed finding doesn't kill the whole batch.
        """
        raise NotImplementedError

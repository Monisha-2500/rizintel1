"""
connectors package — Scanner Connectors Registry
"""

from __future__ import annotations

from typing import Dict, Type
from scanner_agent.connectors.base import BaseScannerConnector
from scanner_agent.connectors.zap_connector import ZapConnector
from scanner_agent.connectors.nuclei_connector import NucleiConnector
from scanner_agent.connectors.wapiti_connector import WapitiConnector

CONNECTOR_REGISTRY: Dict[str, Type[BaseScannerConnector]] = {
    "ZAP": ZapConnector,
    "NUCLEI": NucleiConnector,
    "WAPITI": WapitiConnector,
}


def get_connector(scanner_name: str) -> BaseScannerConnector:
    """Instantiate connector for given scanner name."""
    s_upper = scanner_name.upper()
    cls = CONNECTOR_REGISTRY.get(s_upper)
    if not cls:
        raise KeyError(f"No connector registered for scanner '{scanner_name}'. Supported: {list(CONNECTOR_REGISTRY.keys())}")
    return cls()

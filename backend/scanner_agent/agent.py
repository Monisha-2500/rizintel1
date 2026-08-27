"""
agent.py — Scanner Agent Daemon Loop

Continuous polling agent daemon that:
  1. Discovers and validates local scanner tools (Nuclei, ZAP, Wapiti)
  2. Sends authenticated capability heartbeats to RizIntel backend
  3. Claims QUEUED scanner jobs matching only available local scanners
  4. Delegates execution to JobExecutor
  5. Refreshes capabilities periodically and shuts down cleanly on SIGINT/SIGTERM
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import time
from typing import Any, Dict, List

# Ensure backend directory is in sys.path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from scanner_agent.api_client import ApiClient
from scanner_agent.config import AgentConfig
from scanner_agent.discovery import ScannerDiscovery
from scanner_agent.executor import JobExecutor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
)
logger = logging.getLogger("rizintel.scanner_agent")

_shutdown = False


def _handle_signal(signum, frame):
    global _shutdown
    logger.info("Shutdown signal received (%s). Finishing work and exiting cleanly...", signum)
    _shutdown = True


def probe_capabilities(config: AgentConfig) -> Dict[str, Dict[str, Any]]:
    """Discover real scanner binaries and return structured capabilities."""
    return ScannerDiscovery.discover_all(
        nuclei_path=config.nuclei_executable,
        zap_path=config.zap_executable,
        wapiti_path=config.wapiti_executable,
    )


def main() -> None:
    global _shutdown

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    config = AgentConfig()
    try:
        config.validate()
    except ValueError as e:
        logger.critical("Agent configuration error: %s", e)
        sys.exit(1)

    api = ApiClient(server_url=config.server_url, agent_token=config.agent_token)
    executor = JobExecutor(api_client=api, timeout=config.default_timeout_seconds)

    logger.info("Scanner agent starting — server=%s", config.server_url)

    # Initial capability discovery
    caps = probe_capabilities(config)
    available_scanners = [s for s, c in caps.items() if c.get("available")]
    logger.info("Discovered scanner capabilities: %s", {
        s: f"v{c.get('version')}" if c.get("available") else f"UNAVAILABLE ({c.get('error')})"
        for s, c in caps.items()
    })

    # Send initial capability heartbeat immediately
    if not api.heartbeat(capabilities=caps):
        logger.warning("Initial heartbeat failed — verify server connectivity and agent token.")
    else:
        logger.info("Initial authenticated heartbeat succeeded.")

    last_heartbeat = time.monotonic()
    heartbeat_interval = 30.0

    while not _shutdown:
        now = time.monotonic()

        # Refresh capabilities and send periodic heartbeat
        if now - last_heartbeat >= heartbeat_interval:
            caps = probe_capabilities(config)
            available_scanners = [s for s, c in caps.items() if c.get("available")]
            api.heartbeat(capabilities=caps)
            last_heartbeat = now

        # Claim only jobs matching available scanners
        if not available_scanners:
            logger.debug("No scanner binaries currently available on host. Waiting...")
            time.sleep(config.poll_interval_seconds)
            continue

        job = api.claim_job(capabilities=available_scanners)
        if job:
            scanner_name = job.get("scanner", "")
            timeout = config.get_timeout_for_scanner(scanner_name)
            executor.run(job, scanner_timeout=timeout)
        else:
            time.sleep(config.poll_interval_seconds)

    logger.info("Scanner agent exited cleanly.")


if __name__ == "__main__":
    main()

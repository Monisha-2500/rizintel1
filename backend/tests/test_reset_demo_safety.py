"""
test_reset_demo_safety.py — Safety Verification Test for reset_demo.py (Phase 7)
"""

import os
import pytest
from scripts.reset_demo import reset_demo_database


def test_reset_demo_refuses_production_environment(monkeypatch):
    """
    Verifies that reset_demo_database aborts immediately when RIZINTEL_ENV=production.
    """
    monkeypatch.setenv("RIZINTEL_ENV", "production")

    with pytest.raises(SystemExit) as exc_info:
        reset_demo_database()

    assert exc_info.value.code == 1

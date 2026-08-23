"""
data_loader.py
--------------
OPERATION: Load Findings

Reads the Member 7 input JSON file (produced by Member 6) into memory.
Does not modify the original file in any way.
"""

import json
import os

from . import state
from .config import INPUT_FILE


def loadfindings():
    """Load findings from the Member 7 input JSON file into state.findings."""
    if not os.path.exists(INPUT_FILE):
        print(f"\nERROR: Could not find '{INPUT_FILE}' in this folder.")
        print("Please place the input JSON file next to run_member7.py.\n")
        return

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        state.findings = json.load(f)

    print(f"\nLoaded {len(state.findings)} findings from '{INPUT_FILE}' successfully.\n")

"""
config.py
----------
All the fixed settings for Member 7 live here in one place:
file names, and the SLA warning threshold.
"""

# Input dataset (from Member 6) - must sit next to run_member7.py
INPUT_FILE = "m7_input_explained_findings.json"

# Where generated tickets are optionally saved
OUTPUT_FILE = "member7_output.json"

# How close to the deadline (in hours) counts as an "early warning"
WARNING_THRESHOLD_HOURS = 2

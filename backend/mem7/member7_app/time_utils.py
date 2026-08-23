"""
time_utils.py
-------------
Small helper functions for working with timestamps and durations.
Used by the SLA engine and ticket manager.
"""

from datetime import datetime, timezone


def now_utc():
    """Return the current UTC time as a naive datetime (no tzinfo)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def parse_time(timestamp_str):
    """Convert an ISO 8601 string like '2026-08-13T00:00:00Z' into a datetime."""
    return datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%SZ")


def format_timedelta(delta):
    """Turn a timedelta into a readable string, e.g. '2 days 5 hours 10 minutes'."""
    total_seconds = int(delta.total_seconds())

    if total_seconds <= 0:
        return "0 minutes"

    days = total_seconds // 86400
    hours = (total_seconds % 86400) // 3600
    minutes = (total_seconds % 3600) // 60

    parts = []
    if days > 0:
        parts.append(f"{days} days")
    if hours > 0:
        parts.append(f"{hours} hours")
    if minutes > 0 or not parts:
        parts.append(f"{minutes} minutes")

    return " ".join(parts)

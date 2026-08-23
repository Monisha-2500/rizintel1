#!/usr/bin/env python3
"""
normalize.py
------------
THE common script. Takes any scanner report file, figures out (or is told)
which scanner produced it, and writes normalized JSON — no code editing
required for files from scanners you already have an adapter for.

Usage:
  # Auto-detect format:
  python3 normalize.py report.json

  # Force a specific scanner (skips detection, useful if a file is ambiguous):
  python3 normalize.py report.json --scanner ZAP

  # Merge multiple reports (any mix of scanners) into one normalized file:
  python3 normalize.py zap.json nuclei.json openvas.xml -o merged.json

  # See which scanners are supported:
  python3 normalize.py --list-scanners
"""

import argparse
import json
import sys
from pathlib import Path

from pipeline import NormalizationPipeline
from detect import detect_scanner_format


def main():
    parser = argparse.ArgumentParser(
        description="Convert scanner report(s) into the universal vulnerability schema."
    )
    parser.add_argument("files", nargs="*", help="Path(s) to scanner report file(s)")
    parser.add_argument(
        "--scanner", "-s",
        help="Force a specific scanner adapter instead of auto-detecting (e.g. ZAP, Nuclei, OpenVAS)"
    )
    parser.add_argument(
        "--output", "-o",
        default="normalized_output.json",
        help="Output file path (default: normalized_output.json)"
    )
    parser.add_argument(
        "--list-scanners", action="store_true",
        help="Print registered scanner adapters and exit"
    )
    args = parser.parse_args()

    pipeline = NormalizationPipeline()

    if args.list_scanners:
        print("Registered scanner adapters:")
        for name in pipeline.available_scanners():
            print(f"  - {name}")
        return

    if not args.files:
        parser.print_help()
        sys.exit(1)

    all_findings = []

    for file_path in args.files:
        path = Path(file_path)
        if not path.exists():
            print(f"[!] File not found, skipping: {file_path}")
            continue

        raw_data = path.read_text()
        scanner_name = args.scanner or detect_scanner_format(raw_data)

        if scanner_name is None:
            print(f"[!] Could not detect scanner format for '{file_path}'. "
                  f"Use --scanner to specify it manually. Skipping.")
            continue

        if scanner_name not in pipeline.available_scanners():
            print(f"[!] Detected '{scanner_name}' for '{file_path}', but no adapter is "
                  f"registered for it. Available: {pipeline.available_scanners()}. Skipping.")
            continue

        try:
            findings = pipeline.normalize(scanner_name, raw_data)
            print(f"[✓] {file_path}  →  detected as {scanner_name}  →  {len(findings)} findings")
            all_findings.extend(findings)
        except Exception as e:
            print(f"[!] Failed to normalize '{file_path}' as {scanner_name}: {e}")

    if not all_findings:
        print("\nNo findings normalized. Nothing written.")
        return

    output_path = Path(args.output)
    output_path.write_text(
        json.dumps([json.loads(f.model_dump_json()) for f in all_findings], indent=2)
    )
    print(f"\nWrote {len(all_findings)} standardized findings to {output_path}")


if __name__ == "__main__":
    main()

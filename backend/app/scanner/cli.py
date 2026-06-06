from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .gitleaks_parser import parse_gitleaks_report
from .source_scanner import scan_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="credhunter-scanner")
    subparsers = parser.add_subparsers(dest="command", required=True)

    normalize_parser = subparsers.add_parser("normalize-gitleaks")
    normalize_parser.add_argument("--input", required=True, help="Path to Gitleaks JSON or SARIF report.")
    normalize_parser.add_argument("--output", help="Optional output JSON path.")

    scan_parser = subparsers.add_parser("scan-path")
    scan_parser.add_argument("--path", required=True, help="Repository, folder, or file path to scan.")
    scan_parser.add_argument("--output", help="Optional output JSON path.")

    args = parser.parse_args(argv)

    if args.command == "normalize-gitleaks":
        findings = parse_gitleaks_report(args.input)
    elif args.command == "scan-path":
        findings = scan_path(args.path)
    else:
        parser.error(f"Unknown command: {args.command}")

    payload = {
        "finding_count": len(findings),
        "findings": [finding.to_dict() for finding in findings],
    }
    _write_output(payload, args.output)
    return 0


def _write_output(payload: dict, output_path: str | None) -> None:
    encoded = json.dumps(payload, indent=2, sort_keys=True)
    if output_path:
        Path(output_path).write_text(encoded + "\n", encoding="utf-8")
    else:
        sys.stdout.write(encoded + "\n")


if __name__ == "__main__":
    raise SystemExit(main())

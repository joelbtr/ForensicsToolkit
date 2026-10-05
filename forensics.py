#!/usr/bin/env python3
"""
forensics.py — Disk Image Forensics Toolkit
Subcommands: carve, extract, timeline

Usage:
  python forensics.py carve   disk.img --output carved/
  python forensics.py extract carved/ --output metadata.json
  python forensics.py timeline --carver carver_results.json \
                                --metadata metadata.json \
                                --output report.html
"""

import argparse
import json
import sys
from pathlib import Path

BANNER = """
╔══════════════════════════════════════════════════════╗
║       Forensics Toolkit — Disk Image Analysis        ║
╚══════════════════════════════════════════════════════╝
"""


def cmd_carve(args):
    from carver import carve
    if not Path(args.image).exists():
        print(f"[!] Image not found: {args.image}")
        sys.exit(1)

    results = carve(args.image, args.output, verbose=args.verbose)

    # Save carver results to JSON for the timeline step
    json_out = Path(args.output) / "carver_results.json"
    with open(json_out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[+] Carver results saved to {json_out}")


def cmd_extract(args):
    from extractor import extract_all
    if not Path(args.input).exists():
        print(f"[!] Input directory not found: {args.input}")
        sys.exit(1)

    extract_all(args.input, args.output, verbose=args.verbose)


def cmd_timeline(args):
    from timeline import build_timeline_from_files
    build_timeline_from_files(
        carver_json=args.carver,
        metadata_json=args.metadata,
        output_html=args.output,
        title=args.title,
    )


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Forensics Toolkit — raw disk image analysis"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # carve
    p_carve = sub.add_parser("carve", help="Carve files from a raw disk image")
    p_carve.add_argument("image", help="Path to raw disk image (.dd / .img)")
    p_carve.add_argument("-o", "--output", default="carved", help="Output directory (default: carved/)")
    p_carve.add_argument("-v", "--verbose", action="store_true")

    # extract
    p_extract = sub.add_parser("extract", help="Extract metadata from carved files")
    p_extract.add_argument("input", help="Directory of files to analyse (e.g. carved/)")
    p_extract.add_argument("-o", "--output", default="metadata.json", help="Output JSON file")
    p_extract.add_argument("-v", "--verbose", action="store_true")

    # timeline
    p_timeline = sub.add_parser("timeline", help="Build a chronological HTML timeline report")
    p_timeline.add_argument("--carver", default="carved/carver_results.json", help="Carver results JSON")
    p_timeline.add_argument("--metadata", default="metadata.json", help="Metadata JSON from extract step")
    p_timeline.add_argument("-o", "--output", default="report.html", help="Output HTML report")
    p_timeline.add_argument("--title", default="Disk Image Investigation", help="Report title")

    args = parser.parse_args()

    dispatch = {
        "carve": cmd_carve,
        "extract": cmd_extract,
        "timeline": cmd_timeline,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()

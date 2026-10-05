"""
extractor.py — Metadata extraction from carved or raw files.

Handles three categories:
  1. Images (JPEG, PNG, GIF) — EXIF data via Pillow
  2. PE binaries (EXE, DLL)  — PE header fields via pefile
  3. Any file               — filesystem timestamps, size, entropy

Entropy is a useful forensic signal: high entropy (~8.0) suggests
encryption or compression; low entropy suggests plain text or sparse data.
"""

import os
import math
import struct
import json
from pathlib import Path
from datetime import datetime, timezone


# ------------------------------------------------------------------ #
#  Entropy                                                             #
# ------------------------------------------------------------------ #

def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte string. Range: 0.0 – 8.0."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for f in freq:
        if f > 0:
            p = f / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


# ------------------------------------------------------------------ #
#  EXIF extraction                                                     #
# ------------------------------------------------------------------ #

def _extract_exif(path: str) -> dict:
    """
    Extract EXIF metadata from JPEG/PNG using Pillow.
    Returns a flat dict of tag_name -> value strings.
    Falls back gracefully if Pillow or EXIF data is unavailable.
    """
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
    except ImportError:
        return {"error": "Pillow not installed — run: pip install Pillow"}

    try:
        img = Image.open(path)
        exif_raw = img._getexif()
        if not exif_raw:
            return {"note": "No EXIF data found"}

        exif = {}
        for tag_id, value in exif_raw.items():
            tag = TAGS.get(tag_id, str(tag_id))
            # Convert bytes to hex string for JSON serialisation
            if isinstance(value, bytes):
                value = value.hex()
            # Truncate very long values
            if isinstance(value, str) and len(value) > 200:
                value = value[:200] + "..."
            exif[tag] = str(value)
        return exif
    except Exception as e:
        return {"error": str(e)}


# ------------------------------------------------------------------ #
#  PE header extraction                                                #
# ------------------------------------------------------------------ #

def _extract_pe(path: str) -> dict:
    """
    Extract PE header fields from a Windows executable.
    Uses pefile if available, falls back to manual struct parsing.
    """
    try:
        import pefile
        pe = pefile.PE(path, fast_load=True)
        ts = pe.FILE_HEADER.TimeDateStamp
        compile_time = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else None
        return {
            "compile_timestamp": compile_time,
            "machine": hex(pe.FILE_HEADER.Machine),
            "num_sections": pe.FILE_HEADER.NumberOfSections,
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "sections": [s.Name.decode(errors="replace").rstrip("\x00") for s in pe.sections],
        }
    except ImportError:
        pass

    # Manual fallback: parse the PE header with struct
    try:
        with open(path, "rb") as f:
            data = f.read(512)

        if data[:2] != b"MZ":
            return {"error": "Not a valid PE file"}

        # e_lfanew is at offset 0x3C — points to the PE signature
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data):
            return {"note": "PE header beyond read buffer"}

        machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
        num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        timestamp = struct.unpack_from("<I", data, e_lfanew + 8)[0]
        compile_time = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat() if timestamp else None

        return {
            "compile_timestamp": compile_time,
            "machine": hex(machine),
            "num_sections": num_sections,
            "note": "parsed manually (pefile not installed)",
        }
    except Exception as e:
        return {"error": str(e)}


# ------------------------------------------------------------------ #
#  Main extraction function                                            #
# ------------------------------------------------------------------ #

def extract_metadata(path: str) -> dict:
    """
    Extract all available metadata from a single file.
    Returns a dict suitable for JSON serialisation.
    """
    p = Path(path)
    stat = p.stat()

    # Read up to 1 MB for entropy calculation
    with open(path, "rb") as f:
        sample = f.read(1024 * 1024)

    result = {
        "file": str(p),
        "filename": p.name,
        "size_bytes": stat.st_size,
        "mtime": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        "ctime": datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
        "entropy": _shannon_entropy(sample),
        "magic_bytes": sample[:8].hex(),
    }

    ext = p.suffix.lower()

    if ext in (".jpg", ".jpeg", ".png", ".gif", ".tiff"):
        result["exif"] = _extract_exif(path)

    elif ext in (".exe", ".dll", ".sys"):
        result["pe_header"] = _extract_pe(path)

    return result


def extract_all(input_dir: str, output_json: str, verbose: bool = False) -> list:
    """
    Walk `input_dir`, extract metadata from every file,
    and write results to `output_json`.
    """
    input_dir = Path(input_dir)
    results = []

    files = list(input_dir.rglob("*"))
    files = [f for f in files if f.is_file()]

    print(f"[*] Extracting metadata from {len(files)} files in {input_dir}")

    for f in files:
        try:
            meta = extract_metadata(str(f))
            results.append(meta)
            if verbose:
                print(f"  [+] {f.name:40s}  entropy={meta['entropy']:.2f}  size={meta['size_bytes']:,}")
        except Exception as e:
            results.append({"file": str(f), "error": str(e)})

    with open(output_json, "w", encoding="utf-8") as out:
        json.dump(results, out, indent=2)

    print(f"[+] Metadata written to {output_json}")

    # Flag anything suspicious
    high_entropy = [r for r in results if r.get("entropy", 0) > 7.5]
    if high_entropy:
        print(f"\n[!] {len(high_entropy)} file(s) with high entropy (>7.5) — possible encryption/packing:")
        for r in high_entropy:
            print(f"    {r['file']}  entropy={r['entropy']}")

    return results

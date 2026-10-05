"""
carver.py — Raw disk image file carver.

Reads the image in chunks, scans for known magic byte signatures,
then carves each match out to a file in the output directory.

Two carving strategies:
  - Footer-based: scan forward from the header for the file's known
    end marker (e.g. JPEG ends with FF D9). More accurate.
  - Size-capped: no footer known, so carve a fixed max_size block
    from the header offset. Common for EXE/ELF.
"""

import os
from pathlib import Path
from signatures import SIGNATURES, build_index

# How many bytes to read at a time when scanning.
# Overlap ensures we don't miss signatures that straddle chunk boundaries.
CHUNK_SIZE = 1024 * 1024        # 1 MB per chunk
OVERLAP = 16                     # bytes of overlap between chunks


def _find_footer(data: bytes, footer: bytes, start: int, max_size: int) -> int:
    """
    Search for `footer` bytes in `data` starting at `start`.
    Returns the index of the end of the footer, or start+max_size
    as a fallback if the footer isn't found within range.
    """
    end = min(start + max_size, len(data))
    idx = data.find(footer, start, end)
    if idx == -1:
        return end
    return idx + len(footer)


def carve(image_path: str, output_dir: str, verbose: bool = False) -> list:
    """
    Scan `image_path` for known file signatures and carve matches
    into `output_dir`. Returns a list of result dicts.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    results = []
    sig_index = build_index()
    image_size = os.path.getsize(image_path)

    print(f"[*] Image size: {image_size / (1024*1024):.1f} MB")
    print(f"[*] Output directory: {output_dir}")
    print(f"[*] Scanning for {len(SIGNATURES)} file types...\n")

    # Read the entire image into memory for small images (<500 MB).
    # For larger images you'd use mmap — keeping it simple here.
    if image_size > 500 * 1024 * 1024:
        print("[!] Image >500 MB — consider using mmap for large images.")

    with open(image_path, "rb") as f:
        data = f.read()

    offset = 0
    carved_counts = {}

    while offset < len(data) - 4:
        # Check the next 4 bytes against our index
        window = data[offset:offset + 4]

        matched = False
        for key, sigs in sig_index.items():
            if window[:len(key)] == key:
                for sig in sigs:
                    if data[offset:offset + len(sig["magic"])] == sig["magic"]:
                        matched = True
                        name = sig["name"]
                        ext = sig["extension"]
                        count = carved_counts.get(ext, 0)
                        carved_counts[ext] = count + 1
                        out_name = f"{ext}_{count:04d}.{ext}"
                        out_path = output_dir / out_name

                        # Determine carve end
                        if sig["footer"]:
                            end = _find_footer(data, sig["footer"], offset + len(sig["magic"]), sig["max_size"])
                        else:
                            end = min(offset + sig["max_size"], len(data))

                        carved_data = data[offset:end]

                        with open(out_path, "wb") as out:
                            out.write(carved_data)

                        result = {
                            "file": str(out_path),
                            "type": name,
                            "mime": sig["mime"],
                            "offset": offset,
                            "offset_hex": hex(offset),
                            "size": len(carved_data),
                        }
                        results.append(result)

                        if verbose:
                            print(f"  [+] {name:30s}  offset={hex(offset):10s}  size={len(carved_data):,} bytes  -> {out_name}")

                        # Skip past what we just carved
                        offset = end
                        break

            if matched:
                break

        if not matched:
            offset += 1

    print(f"\n[+] Carving complete. {len(results)} files recovered.")
    _print_summary(carved_counts)
    return results


def _print_summary(counts: dict):
    if not counts:
        print("    No files found.")
        return
    print("\n    Summary:")
    for ext, count in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"      {ext.upper():10s} {count} file(s)")

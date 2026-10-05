# Forensics Toolkit

A Python toolkit for raw disk image forensics. Three stages: carve, extract, timeline.

---

## Installation

```bash
git clone https://github.com/yourname/forensics-toolkit
cd forensics-toolkit
pip install -r requirements.txt
```

`Pillow` handles EXIF extraction from images. `pefile` handles PE header parsing from Windows executables. Both are optional — the toolkit degrades gracefully without them using manual fallbacks.

---

## Workflow

### 1. Carve files from a raw image

```bash
python forensics.py carve disk.img --output carved/ --verbose
```

Scans the image byte by byte for known magic byte signatures (JPEG, PNG, PDF, ZIP, EXE, ELF, SQLite, and more). Carves each match to `carved/` and saves a `carver_results.json` summary.

**Output:**
```
[*] Image size: 512.0 MB
[*] Scanning for 10 file types...

  [+] JPEG        offset=0x4a200    size=142,334 bytes  -> jpg_0000.jpg
  [+] PDF         offset=0x1f4000   size=48,210 bytes   -> pdf_0000.pdf
  [+] Windows PE  offset=0x3a1000   size=102,400 bytes  -> exe_0000.exe

[+] Carving complete. 3 files recovered.

    Summary:
      JPEG       1 file(s)
      PDF        1 file(s)
      EXE        1 file(s)
```

### 2. Extract metadata

```bash
python forensics.py extract carved/ --output metadata.json --verbose
```

Walks the carved directory and extracts:
- Filesystem timestamps (mtime, ctime)
- Shannon entropy (high entropy flags encrypted/packed files)
- EXIF data from images (GPS, DateTimeOriginal, camera model)
- PE header fields from executables (compile timestamp, machine type, sections)

**Entropy interpretation:**

| Entropy | Meaning |
|---|---|
| 0.0 – 2.0 | Highly repetitive / sparse (zeroed blocks) |
| 4.0 – 6.0 | Normal executable or document |
| 7.5 – 8.0 | Likely encrypted, packed, or compressed |

### 3. Build the timeline

```bash
python forensics.py timeline \
  --carver carved/carver_results.json \
  --metadata metadata.json \
  --title "Case 001 — USB Drive" \
  --output report.html
```

Merges all events, sorts chronologically, and produces a self-contained HTML report showing every file event on a visual timeline with source badges (carved / filesystem / PE header / EXIF).

---

## Typical full run

```bash
# Acquire the image first (outside this tool)
dd if=/dev/sdb of=suspect.img bs=4M status=progress

# Then run all three stages
python forensics.py carve   suspect.img -o carved/ -v
python forensics.py extract carved/ -o metadata.json -v
python forensics.py timeline --title "Suspect USB" -o report.html

# Open the report
xdg-open report.html   # Linux
start report.html      # Windows
```

---

## Supported file types

| Type | Magic bytes | Footer-based carving |
|---|---|---|
| JPEG | `FF D8 FF` | Yes (`FF D9`) |
| PNG | `89 PNG 0D 0A 1A 0A` | Yes (IEND chunk) |
| GIF | `GIF8` | Yes (`00 3B`) |
| PDF | `%PDF` | Yes (`%%EOF`) |
| ZIP / DOCX | `PK 03 04` | Yes (`PK 05 06`) |
| Windows PE | `MZ` | No (size-capped) |
| ELF binary | `7F ELF` | No (size-capped) |
| SQLite | `SQLite format 3` | No (size-capped) |
| MP4 | `00 00 00 18 ftyp` | No (size-capped) |

---

## Project structure

```
forensics-toolkit/
├── forensics.py      # CLI entry point
├── carver.py         # Magic byte scanning and file carving
├── extractor.py      # EXIF, PE header, entropy extraction
├── timeline.py       # Event aggregation and HTML report
├── signatures.py     # Magic byte database
├── requirements.txt
└── README.md
```

---

## Forensic context

This toolkit replicates the core functions of professional tools like Autopsy, Foremost, and Scalpel — in pure Python, from scratch. Key concepts demonstrated:

- **File carving**: recovering files from unallocated disk space using header/footer signatures, without relying on the filesystem. Used in real investigations where the FAT/MFS/ext4 metadata has been wiped.
- **Shannon entropy**: a one-pass measure of randomness in a byte sequence. Encrypted files and packed executables approach maximum entropy (8.0). Useful for triaging a large carve dump quickly.
- **PE timestamp forensics**: Windows executables embed a compile timestamp in the COFF header. This is often forged, but comparing it against filesystem timestamps and network logs can reveal inconsistencies.
- **EXIF GPS extraction**: digital photos embed GPS coordinates, camera model, and capture time in EXIF metadata. This is a common source of evidence in both criminal and corporate investigations.
- **Timeline correlation**: the most important step — merging events from multiple sources (filesystem, binary headers, embedded metadata) into a single chronological view to reconstruct what happened and when.

---

## License

MIT

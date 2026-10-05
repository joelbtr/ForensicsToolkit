"""
signatures.py — File type magic byte database.

Each entry defines:
  - magic:    bytes to match at the start of a file (header)
  - extension: file extension to use when carving
  - mime:     MIME type string for reporting
  - footer:   optional bytes marking the end of the file
  - max_size: maximum carve size in bytes (safety cap)
"""

SIGNATURES = [
    {
        "name": "JPEG",
        "magic": b"\xff\xd8\xff",
        "extension": "jpg",
        "mime": "image/jpeg",
        "footer": b"\xff\xd9",
        "max_size": 10 * 1024 * 1024,  # 10 MB
    },
    {
        "name": "PNG",
        "magic": b"\x89PNG\r\n\x1a\n",
        "extension": "png",
        "mime": "image/png",
        "footer": b"\x49\x45\x4e\x44\xae\x42\x60\x82",  # IEND chunk
        "max_size": 10 * 1024 * 1024,
    },
    {
        "name": "GIF",
        "magic": b"GIF8",
        "extension": "gif",
        "mime": "image/gif",
        "footer": b"\x00\x3b",
        "max_size": 5 * 1024 * 1024,
    },
    {
        "name": "PDF",
        "magic": b"%PDF",
        "extension": "pdf",
        "mime": "application/pdf",
        "footer": b"%%EOF",
        "max_size": 50 * 1024 * 1024,  # 50 MB
    },
    {
        "name": "ZIP",
        "magic": b"PK\x03\x04",
        "extension": "zip",
        "mime": "application/zip",
        "footer": b"PK\x05\x06",
        "max_size": 100 * 1024 * 1024,
    },
    {
        "name": "Windows PE (EXE/DLL)",
        "magic": b"MZ",
        "extension": "exe",
        "mime": "application/x-msdownload",
        "footer": None,
        "max_size": 20 * 1024 * 1024,
    },
    {
        "name": "ELF binary",
        "magic": b"\x7fELF",
        "extension": "elf",
        "mime": "application/x-elf",
        "footer": None,
        "max_size": 20 * 1024 * 1024,
    },
    {
        "name": "SQLite database",
        "magic": b"SQLite format 3\x00",
        "extension": "sqlite",
        "mime": "application/x-sqlite3",
        "footer": None,
        "max_size": 50 * 1024 * 1024,
    },
    {
        "name": "MP4 video",
        "magic": b"\x00\x00\x00\x18ftypmp4",
        "extension": "mp4",
        "mime": "video/mp4",
        "footer": None,
        "max_size": 500 * 1024 * 1024,
    },
    {
        "name": "DOCX / Office Open XML",
        "magic": b"PK\x03\x04",   # same as ZIP — differentiated by extractor
        "extension": "docx",
        "mime": "application/vnd.openxmlformats-officedocument",
        "footer": b"PK\x05\x06",
        "max_size": 50 * 1024 * 1024,
    },
]

# Build a quick lookup: first N bytes -> list of matching signatures
# Used by the carver to avoid scanning every signature for every byte.
def build_index():
    index = {}
    for sig in SIGNATURES:
        key = sig["magic"][:4]
        index.setdefault(key, []).append(sig)
    return index

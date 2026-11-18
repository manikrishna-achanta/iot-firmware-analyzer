"""
modules/extractor.py
Extracts filesystem contents from firmware images using binwalk-style
signature detection and Python-native decompression where possible.
Falls back to calling system binwalk/dd if available.
"""

import os
import json
import struct
import zlib
import gzip
import shutil
import subprocess
import tempfile


# ── Filesystem / Archive Signatures ──────────────────────────────────────────

SIGNATURES = [
    {"magic": b"hsqs",             "name": "SquashFS",      "offset": 0},
    {"magic": b"sqsh",             "name": "SquashFS",      "offset": 0},
    {"magic": b"\x1f\x8b",        "name": "Gzip",          "offset": 0},
    {"magic": b"BZh",             "name": "Bzip2",          "offset": 0},
    {"magic": b"\xfd7zXZ\x00",    "name": "XZ",             "offset": 0},
    {"magic": b"PK\x03\x04",      "name": "ZIP",            "offset": 0},
    {"magic": b"UBI#",            "name": "UBIFS",          "offset": 0},
    {"magic": b"\x45\x3d\xcd\x28","name": "SquashFS-v1",    "offset": 0},
    {"magic": b"070701",          "name": "CPIO",           "offset": 0},
    {"magic": b"070707",          "name": "CPIO (old)",     "offset": 0},
    {"magic": b"\x27\x05\x19\x56","name": "U-Boot Legacy",  "offset": 0},
    {"magic": b"\x7fELF",         "name": "ELF Binary",     "offset": 0},
    {"magic": b"JFFS2",           "name": "JFFS2",          "offset": 0},
    {"magic": b"\x19\x85",        "name": "JFFS2 (BE)",     "offset": 0},
    {"magic": b"\x85\x19",        "name": "JFFS2 (LE)",     "offset": 0},
]


def _scan_for_signatures(data):
    """Scan binary for known filesystem/archive signatures."""
    found = []
    for sig in SIGNATURES:
        magic = sig["magic"]
        offset = 0
        while True:
            pos = data.find(magic, offset)
            if pos == -1:
                break
            found.append({
                "name"   : sig["name"],
                "offset" : pos,
                "offset_h": hex(pos),
                "magic"  : magic.hex(),
            })
            offset = pos + 1
    # Sort by offset
    found.sort(key=lambda x: x["offset"])
    # Deduplicate overlapping hits
    deduped = []
    last = -1
    for f in found:
        if f["offset"] > last + 4:
            deduped.append(f)
            last = f["offset"]
    return deduped


def _try_gzip_extract(data, offset, out_dir):
    """Attempt to decompress a gzip stream at the given offset."""
    try:
        compressed = data[offset:]
        decompressed = gzip.decompress(compressed)
        out_path = os.path.join(out_dir, f"gzip_at_{hex(offset)}.bin")
        with open(out_path, "wb") as f:
            f.write(decompressed)
        return out_path, len(decompressed)
    except Exception as e:
        return None, str(e)


def _try_zlib_extract(data, offset, out_dir):
    """Attempt to decompress a zlib stream at the given offset."""
    try:
        compressed = data[offset:]
        decompressed = zlib.decompress(compressed)
        out_path = os.path.join(out_dir, f"zlib_at_{hex(offset)}.bin")
        with open(out_path, "wb") as f:
            f.write(decompressed)
        return out_path, len(decompressed)
    except Exception:
        return None, None


def _carve_region(data, offset, out_dir, name):
    """Carve a raw region from firmware for manual inspection."""
    chunk = data[offset:offset + 1024 * 1024]  # up to 1MB
    out_path = os.path.join(out_dir, f"carved_{name.replace(' ','_')}_{hex(offset)}.bin")
    with open(out_path, "wb") as f:
        f.write(chunk)
    return out_path


def _try_binwalk(firmware_path, out_dir):
    """Try to use system binwalk if installed."""
    if not shutil.which("binwalk"):
        return None, "binwalk not installed"
    try:
        result = subprocess.run(
            ["binwalk", "--extract", "--directory", out_dir, firmware_path],
            capture_output=True, text=True, timeout=60
        )
        return result.stdout[:2000], result.returncode
    except Exception as e:
        return None, str(e)


def extract_firmware(firmware_path, session_dir):
    """
    Attempt to extract filesystem from firmware image.
    1. Scan for signatures
    2. Attempt Python-native decompression
    3. Fall back to binwalk if available
    Returns dict of findings.
    """
    with open(firmware_path, "rb") as f:
        data = f.read()

    extract_dir = os.path.join(session_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)

    result = {
        "signatures_found" : [],
        "extractions"      : [],
        "binwalk_output"   : "",
        "binwalk_used"     : False,
        "extract_dir"      : extract_dir,
    }

    # ── 1. Signature scan ─────────────────────────────────────────────────────
    sigs = _scan_for_signatures(data)
    result["signatures_found"] = sigs

    if sigs:
        print(f"  [+] Found {len(sigs)} signature(s):")
        for s in sigs:
            print(f"      {s['offset_h']:10s}  {s['name']}")
    else:
        print("  [-] No known filesystem signatures found.")

    # ── 2. Python-native extraction ───────────────────────────────────────────
    for sig in sigs:
        name   = sig["name"]
        offset = sig["offset"]

        if name == "Gzip":
            out, size = _try_gzip_extract(data, offset, extract_dir)
            if out:
                print(f"  [+] Gzip extracted: {os.path.basename(out)} ({size:,} bytes)")
                result["extractions"].append({"type": "gzip", "output": out, "size": size})
            else:
                # Carve it anyway
                carved = _carve_region(data, offset, extract_dir, name)
                result["extractions"].append({"type": "carve", "output": carved})

        elif name in ("SquashFS", "SquashFS-v1", "UBIFS", "JFFS2", "JFFS2 (BE)", "JFFS2 (LE)", "CPIO"):
            carved = _carve_region(data, offset, extract_dir, name)
            print(f"  [>] {name} carved at {hex(offset)} → {os.path.basename(carved)}")
            print(f"      (Use 'unsquashfs' or 'jefferson' to mount this file)")
            result["extractions"].append({"type": "carve", "fs": name, "output": carved})

        elif name == "ZIP":
            carved = _carve_region(data, offset, extract_dir, name)
            print(f"  [>] ZIP carved at {hex(offset)} → {os.path.basename(carved)}")
            result["extractions"].append({"type": "carve", "fs": "ZIP", "output": carved})

        elif name == "ELF Binary":
            carved = _carve_region(data, offset, extract_dir, name)
            print(f"  [>] ELF binary carved at {hex(offset)} → {os.path.basename(carved)}")
            result["extractions"].append({"type": "elf", "output": carved})

    # ── 3. Try binwalk ────────────────────────────────────────────────────────
    bw_out, bw_code = _try_binwalk(firmware_path, extract_dir)
    if bw_out:
        result["binwalk_used"]   = True
        result["binwalk_output"] = bw_out
        print(f"  [+] binwalk extraction complete (exit code: {bw_code})")
        print(f"  [>] Extracted files in: {extract_dir}")
    else:
        print(f"  [~] binwalk: {bw_code}")
        print(f"      Install with: sudo apt install binwalk")

    # List extracted files
    extracted_files = []
    for root, dirs, files in os.walk(extract_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            extracted_files.append({
                "path" : fpath,
                "size" : os.path.getsize(fpath),
            })

    result["extracted_files"] = extracted_files
    print(f"  [+] Total extracted files: {len(extracted_files)}")

    # Save
    out = os.path.join(session_dir, "extraction.json")
    with open(out, "w") as f:
        json.dump({k: v for k, v in result.items()
                   if k != "extracted_files"}, f, indent=2)
    print(f"  [>] Extraction results → extraction.json")

    return result

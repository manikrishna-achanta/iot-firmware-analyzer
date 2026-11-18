"""
modules/entropy_calc.py
Calculates Shannon entropy across firmware to detect
encrypted, compressed, or packed regions.
"""

import os
import json
import math
from collections import Counter


def _shannon_entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    total  = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def calc_entropy(firmware_path, session_dir, block_size=256):
    """
    Calculate per-block entropy across the firmware image.
    Returns dict with overall entropy, block results, and flagged regions.
    """
    with open(firmware_path, "rb") as f:
        data = f.read()

    total_size    = len(data)
    overall_ent   = _shannon_entropy(data)
    sections      = []
    high_regions  = []

    # Sliding window analysis
    for offset in range(0, total_size, block_size):
        block = data[offset:offset + block_size]
        if len(block) < 16:
            break
        ent = _shannon_entropy(block)
        entry = {
            "offset"  : offset,
            "offset_h": hex(offset),
            "size"    : len(block),
            "entropy" : round(ent, 4),
        }
        sections.append(entry)
        if ent > 7.2:
            high_regions.append(entry)

    # Classify overall entropy
    if overall_ent > 7.5:
        classification = "ENCRYPTED or heavily compressed (very high entropy)"
    elif overall_ent > 6.5:
        classification = "Likely compressed or mixed binary/data"
    elif overall_ent > 5.0:
        classification = "Mixed binary with code and data sections"
    else:
        classification = "Mostly plaintext or repetitive data (low entropy)"

    print(f"  [+] Overall entropy : {overall_ent:.4f} — {classification}")
    print(f"  [+] Blocks analysed : {len(sections)} ({block_size}-byte blocks)")
    print(f"  [+] High-entropy (>7.2) blocks: {len(high_regions)}")

    if high_regions:
        print(f"  [!] Possible encrypted/compressed region at offsets:")
        for r in high_regions[:5]:
            print(f"      {r['offset_h']}  entropy={r['entropy']}")
        if len(high_regions) > 5:
            print(f"      ... and {len(high_regions)-5} more")

    result = {
        "overall_entropy"   : round(overall_ent, 4),
        "classification"    : classification,
        "block_size"        : block_size,
        "total_blocks"      : len(sections),
        "high_entropy_count": len(high_regions),
        "sections"          : sections,
        "high_regions"      : high_regions[:20],
    }

    # Save
    out = os.path.join(session_dir, "entropy.json")
    with open(out, "w") as f:
        json.dump(result, f, indent=2)
    print(f"  [>] Entropy data → entropy.json")

    # Save CSV for plotting
    csv_path = os.path.join(session_dir, "entropy_blocks.csv")
    with open(csv_path, "w") as f:
        f.write("offset,entropy\n")
        for s in sections:
            f.write(f"{s['offset']},{s['entropy']}\n")
    print(f"  [>] Entropy CSV  → entropy_blocks.csv")

    return result

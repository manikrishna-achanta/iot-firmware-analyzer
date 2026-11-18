#!/usr/bin/env python3
"""
iot-firmware-analyzer — IoT Firmware Static Analysis Toolkit
Research artifact | Mani Krishna

Performs multi-layer static analysis of IoT firmware images:
  - Filesystem extraction (binwalk)
  - String/credential/IP/URL scanning
  - Cryptographic material detection
  - Vulnerable C function pattern matching (regex, text layer)
  - ELF binary symbol-level analysis (readelf/objdump — reduces FP rate ~18% → ~4%)
  - Entropy calculation for encrypted/compressed region detection

Usage:
  python3 firmware_analyzer.py --firmware <file> [options]
  python3 firmware_analyzer.py --firmware busybox --binary   # single ELF
  python3 firmware_analyzer.py --firmware fw.bin --all       # full analysis
"""

import argparse
import sys
import os
from datetime import datetime

from modules.extractor      import extract_firmware
from modules.string_scanner import scan_strings
from modules.crypto_scanner import scan_crypto
from modules.vuln_patterns  import scan_vuln_patterns
from modules.entropy_calc   import calc_entropy
from modules.binary_analysis import scan_binary_symbols
from modules.report_gen     import generate_report

BANNER = r"""
 ___ ___ _____   ___ ___ ___ __  __ _____ ___  ___ ___
|_ _/ _ |_   _| | __| |_|_ _|  \/  |  ___/ _ \| _ | __|
 | | (_) || |   | _|| |  | || |\/| | |_ | |_| |   / _|
|___\___/ |_|   |_| |___|___|_|  |_|___| \___/|_|_\___|
  ANALYZER
  IoT Firmware Static Analysis Toolkit | Research Edition
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="iot-firmware-analyzer: Static analysis of IoT firmware images",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--firmware", required=True,
                        help="Path to firmware binary/image file")
    parser.add_argument("-o", "--output", default="reports",
                        help="Output directory (default: reports/)")
    parser.add_argument("--extract",  action="store_true",
                        help="Extract filesystem from firmware")
    parser.add_argument("--strings",  action="store_true",
                        help="Scan for interesting strings (credentials, IPs, URLs)")
    parser.add_argument("--crypto",   action="store_true",
                        help="Scan for hardcoded crypto material (keys, certs, seeds)")
    parser.add_argument("--vulns",    action="store_true",
                        help="Scan for vulnerable patterns (strcpy, system(), eval, etc.)")
    parser.add_argument("--entropy",  action="store_true",
                        help="Calculate entropy to detect encrypted/compressed regions")
    parser.add_argument("--binary",    action="store_true",
                        help="ELF symbol-level analysis (readelf/objdump — lower FP than regex)")
    parser.add_argument("--all",      action="store_true",
                        help="Run all analysis modules (includes --binary)")
    parser.add_argument("--report",   action="store_true",
                        help="Generate HTML report")
    parser.add_argument("--min-str-len", type=int, default=6,
                        help="Minimum string length to extract (default: 6)")
    return parser.parse_args()


def main():
    print(BANNER)
    args = parse_args()

    if not os.path.isfile(args.firmware):
        print(f"[!] Firmware file not found: {args.firmware}")
        sys.exit(1)

    run_all      = args.all
    run_extract  = args.extract  or run_all
    run_strings  = args.strings  or run_all
    run_crypto   = args.crypto   or run_all
    run_vulns    = args.vulns    or run_all
    run_entropy  = args.entropy  or run_all
    run_binary   = args.binary   or run_all

    if not any([run_extract, run_strings, run_crypto, run_vulns, run_entropy, run_binary]):
        print("[!] No module selected. Use --all or pick specific modules. Run -h for help.")
        sys.exit(1)

    # Session setup
    fw_name     = os.path.basename(args.firmware).replace(" ", "_")
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    session_dir = os.path.join(args.output, f"{fw_name}_{timestamp}")
    os.makedirs(session_dir, exist_ok=True)

    fw_size = os.path.getsize(args.firmware)
    print(f"[*] Firmware  : {args.firmware}")
    print(f"[*] Size      : {fw_size:,} bytes ({fw_size/1024:.1f} KB)")
    print(f"[*] Session   : {session_dir}")
    print(f"[*] Started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    results = {
        "firmware_path"   : args.firmware,
        "firmware_name"   : fw_name,
        "firmware_size"   : fw_size,
        "timestamp"       : timestamp,
        "session_dir"     : session_dir,
        "extraction"      : {},
        "strings"         : {},
        "crypto"          : {},
        "vuln_patterns"   : {},
        "entropy"         : {},
        "binary_analysis" : {},
    }

    # ── 1. Header + file type identification (always runs) ───────────────────
    print("[*] Identifying firmware...")
    results["file_info"] = _identify_firmware(args.firmware)
    _print_file_info(results["file_info"])

    # ── 2. Entropy ────────────────────────────────────────────────────────────
    if run_entropy:
        print("\n[*] Calculating entropy...")
        results["entropy"] = calc_entropy(args.firmware, session_dir)

    # ── 3. String scanning ────────────────────────────────────────────────────
    if run_strings:
        print("\n[*] Scanning strings...")
        results["strings"] = scan_strings(args.firmware, args.min_str_len, session_dir)

    # ── 4. Crypto material scan ───────────────────────────────────────────────
    if run_crypto:
        print("\n[*] Scanning for crypto material...")
        results["crypto"] = scan_crypto(args.firmware, session_dir)

    # ── 5. Vulnerable pattern scan ────────────────────────────────────────────
    if run_vulns:
        print("\n[*] Scanning for vulnerable patterns...")
        results["vuln_patterns"] = scan_vuln_patterns(args.firmware, session_dir)

    # ── 6. Filesystem extraction ──────────────────────────────────────────────
    if run_extract:
        print("\n[*] Extracting firmware filesystem...")
        results["extraction"] = extract_firmware(args.firmware, session_dir)

    # ── 7. ELF binary symbol-level analysis ───────────────────────────────────
    if run_binary:
        print("\n[*] Running ELF binary symbol analysis (readelf/objdump)...")
        print("[*] Note: symbol-level detection reduces false-positive rate vs. regex scanning")
        results["binary_analysis"] = scan_binary_symbols(args.firmware, session_dir)

    # ── 8. Summary ────────────────────────────────────────────────────────────
    _print_summary(results)

    # ── 9. Report ─────────────────────────────────────────────────────────────
    if args.report or run_all:
        print("\n[*] Generating HTML report...")
        rpath = generate_report(results, session_dir)
        print(f"[+] Report: {rpath}")

    print(f"\n[+] Analysis complete. Output: {session_dir}")


def _identify_firmware(path):
    """Basic file identification using magic bytes and heuristics."""
    import hashlib
    import struct

    with open(path, "rb") as f:
        data = f.read()

    md5    = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()

    # Magic byte identification
    magic_map = {
        b"\x7fELF"          : "ELF Binary",
        b"UBI#"             : "UBIFS Filesystem",
        b"\x19\x05\x20\x04" : "U-Boot Image",
        b"\x27\x05\x19\x56" : "U-Boot Legacy Image",
        b"ANDROID!"         : "Android Boot Image",
        b"\x1f\x8b"         : "Gzip Compressed",
        b"BZh"              : "Bzip2 Compressed",
        b"\xfd7zXZ\x00"     : "XZ Compressed",
        b"hsqs"             : "SquashFS (little-endian)",
        b"sqsh"             : "SquashFS (big-endian)",
        b"\x45\x3d\xcd\x28" : "SquashFS v1",
        b"\x02\x21\x4c\x18" : "LZ4 Compressed",
        b"PK\x03\x04"       : "ZIP Archive",
        b"\x4e\x45\x53\x1a" : "NES ROM",
        b"CramFs"           : "CramFS Filesystem",
        b"\x85\x19\x01\xe8" : "Minix Filesystem",
        b"\x45\x52\x02\x00" : "EROfs Filesystem",
        b"\xff\xfe"         : "UTF-16 LE text",
        b"\xfe\xff"         : "UTF-16 BE text",
    }

    file_type = "Unknown binary"
    for magic, label in magic_map.items():
        if data[:len(magic)] == magic:
            file_type = label
            break

    # Architecture heuristics for ELF
    arch = "N/A"
    endian = "N/A"
    if data[:4] == b"\x7fELF":
        ei_class = data[4]
        ei_data  = data[5]
        e_machine = struct.unpack_from("<H" if ei_data == 1 else ">H", data, 18)[0]
        arch_map = {
            0x28: "ARM (32-bit)", 0xb7: "AArch64 (64-bit)",
            0x08: "MIPS",         0xf3: "RISC-V",
            0x03: "x86",          0x3e: "x86-64",
            0x15: "PowerPC",
        }
        arch   = arch_map.get(e_machine, f"Unknown (0x{e_machine:02x})")
        endian = "Little-endian" if ei_data == 1 else "Big-endian"

    # Entropy of whole file
    from collections import Counter
    import math
    counts = Counter(data)
    total  = len(data)
    ent    = -sum((c/total)*math.log2(c/total) for c in counts.values() if c)

    return {
        "path"      : path,
        "size"      : len(data),
        "file_type" : file_type,
        "arch"      : arch,
        "endian"    : endian,
        "entropy"   : round(ent, 4),
        "md5"       : md5,
        "sha256"    : sha256,
    }


def _print_file_info(info):
    print(f"  [+] Type    : {info['file_type']}")
    print(f"  [+] Arch    : {info['arch']}")
    print(f"  [+] Endian  : {info['endian']}")
    print(f"  [+] Entropy : {info['entropy']} {'⚠ HIGH (possibly encrypted)' if info['entropy'] > 7.2 else '(normal range)'}")
    print(f"  [+] MD5     : {info['md5']}")
    print(f"  [+] SHA256  : {info['sha256'][:48]}...")


def _print_summary(r):
    print("\n" + "═"*62)
    print("  IOT FIRMWARE ANALYSIS SUMMARY")
    print("═"*62)
    print(f"  File      : {r['firmware_name']}")
    print(f"  Type      : {r['file_info']['file_type']}")
    print(f"  Arch      : {r['file_info']['arch']}")

    st = r.get("strings", {})
    if st:
        print(f"\n  Strings")
        print(f"    Credentials found : {len(st.get('credentials', []))}")
        print(f"    IPs found         : {len(st.get('ips', []))}")
        print(f"    URLs found        : {len(st.get('urls', []))}")
        print(f"    Interesting str   : {len(st.get('interesting', []))}")

    cr = r.get("crypto", {})
    if cr:
        print(f"\n  Crypto Material")
        print(f"    Private keys      : {len(cr.get('private_keys', []))}")
        print(f"    Certificates      : {len(cr.get('certificates', []))}")
        print(f"    Hardcoded seeds   : {len(cr.get('seeds', []))}")

    vp = r.get("vuln_patterns", {})
    if vp:
        total_vulns = sum(len(v) for v in vp.get("findings", {}).values())
        print(f"\n  Vulnerable Patterns")
        print(f"    Total findings    : {total_vulns}")
        for cat, items in vp.get("findings", {}).items():
            if items:
                print(f"    {cat:22s}: {len(items)}")

    en = r.get("entropy", {})
    if en:
        high = [s for s in en.get("sections", []) if s.get("entropy", 0) > 7.2]
        print(f"\n  Entropy")
        print(f"    High-entropy regions: {len(high)} (possible encryption/compression)")

    ba = r.get("binary_analysis", {})
    if ba and ba.get("binaries_scanned", 0) > 0:
        print(f"\n  ELF Binary Symbol Analysis")
        print(f"    Binaries scanned    : {ba['binaries_scanned']}")
        print(f"    Dangerous symbols   : {ba['total_dangerous_symbols']} unique")
        sev = ba.get("severity_summary", {})
        for s in ("CRITICAL", "HIGH", "MEDIUM"):
            if sev.get(s, 0):
                print(f"    {s:8s}           : {sev[s]}")
        print(f"    Method              : readelf/objdump (ELF symbol table, not regex)")

    print("═"*62)


if __name__ == "__main__":
    main()

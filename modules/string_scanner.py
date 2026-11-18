"""
modules/string_scanner.py
Extracts and categorises interesting strings from firmware binaries.
Looks for credentials, IPs, URLs, shell commands, usernames, file paths.
"""

import os
import re
import json


# ── Patterns ──────────────────────────────────────────────────────────────────

PATTERNS = {
    "credentials": [
        r"password\s*[=:]\s*\S+",
        r"passwd\s*[=:]\s*\S+",
        r"pass\s*[=:]\s*\S+",
        r"pwd\s*[=:]\s*\S+",
        r"secret\s*[=:]\s*\S+",
        r"api[_-]?key\s*[=:]\s*\S+",
        r"token\s*[=:]\s*\S+",
        r"auth\s*[=:]\s*\S+",
        r"admin:[^\s]{2,}",
        r"root:[^\s]{2,}",
        r"default[_-]?pass\w*\s*[=:]\s*\S+",
    ],
    "ips": [
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
    ],
    "urls": [
        r"https?://[^\s\"'<>]{4,}",
        r"ftp://[^\s\"'<>]{4,}",
        r"mqtt://[^\s\"'<>]{4,}",
        r"coap://[^\s\"'<>]{4,}",
    ],
    "shell_commands": [
        r"/bin/sh\b",
        r"/bin/bash\b",
        r"/bin/busybox\b",
        r"wget\s+http",
        r"curl\s+http",
        r"chmod\s+[0-9]+",
        r"nc\s+-[le]",
        r"telnet\s+\d",
        r"tftp\s+",
    ],
    "interesting": [
        r"debug[_-]?mode",
        r"backdoor",
        r"hardcoded",
        r"telnet",
        r"enable[d]?\s+by\s+default",
        r"factory[_-]?reset",
        r"ssh[_-]?key",
        r"private[_-]?key",
        r"BEGIN\s+(RSA|EC|DSA|OPENSSH)",
        r"/etc/passwd",
        r"/etc/shadow",
        r"/proc/",
        r"NVRAM",
        r"firmware[_-]?update",
        r"remote[_-]?access",
        r"UART",
        r"JTAG",
    ],
    "file_paths": [
        r"/etc/[a-zA-Z0-9_/\-\.]+",
        r"/var/[a-zA-Z0-9_/\-\.]+",
        r"/tmp/[a-zA-Z0-9_/\-\.]+",
        r"/usr/[a-zA-Z0-9_/\-\.]+",
        r"/www/[a-zA-Z0-9_/\-\.]+",
        r"C:\\[a-zA-Z0-9_\\\.]+",
    ],
}

# Private IPs to flag specifically
PRIVATE_IP_RANGES = [
    r"^192\.168\.",
    r"^10\.",
    r"^172\.(1[6-9]|2\d|3[01])\.",
    r"^127\.",
    r"^0\.0\.0\.0$",
]


def _extract_printable_strings(data, min_len=6):
    """Extract printable ASCII strings from binary data."""
    result = []
    current = []
    for byte in data:
        if 32 <= byte <= 126:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                result.append("".join(current))
            current = []
    if len(current) >= min_len:
        result.append("".join(current))
    return result


def scan_strings(firmware_path, min_len, session_dir):
    """
    Scan firmware for interesting strings.
    Returns categorised findings dict.
    """
    with open(firmware_path, "rb") as f:
        data = f.read()

    strings = _extract_printable_strings(data, min_len)
    print(f"  [>] Extracted {len(strings):,} printable strings (min length: {min_len})")

    findings = {cat: [] for cat in PATTERNS}
    seen = {cat: set() for cat in PATTERNS}

    for s in strings:
        for category, pats in PATTERNS.items():
            for pat in pats:
                matches = re.findall(pat, s, re.IGNORECASE)
                for m in matches:
                    if m not in seen[category]:
                        seen[category].add(m)
                        findings[category].append({
                            "match"   : m,
                            "context" : s[:120],
                        })

    # Flag private IPs separately
    private_ips = []
    for entry in findings.get("ips", []):
        ip = entry["match"]
        if any(re.match(r, ip) for r in PRIVATE_IP_RANGES):
            private_ips.append(ip)

    findings["private_ips"] = private_ips

    # Print summary
    for cat, items in findings.items():
        if items:
            print(f"  [+] {cat:20s}: {len(items)} finding(s)")

    # Save all strings
    all_str_path = os.path.join(session_dir, "all_strings.txt")
    with open(all_str_path, "w") as f:
        f.write(f"# All extracted strings ({len(strings)} total)\n\n")
        f.write("\n".join(strings))

    # Save categorised findings
    findings_path = os.path.join(session_dir, "string_findings.json")
    with open(findings_path, "w") as f:
        json.dump(findings, f, indent=2)

    print(f"  [>] Saved {len(strings):,} strings to all_strings.txt")
    print(f"  [>] Categorised findings → string_findings.json")

    return findings

"""
modules/vuln_patterns.py
Scans firmware binary for known vulnerable function calls, dangerous
patterns, and common IoT misconfigurations using string pattern matching.
"""

import os
import re
import json

# ── Vulnerability Pattern Database ───────────────────────────────────────────

VULN_PATTERNS = {
    "dangerous_functions": {
        "description": "Unsafe C library functions known to cause buffer overflows",
        "severity"   : "HIGH",
        "patterns"   : [
            r"\bstrcpy\b", r"\bstrcat\b", r"\bsprintf\b",
            r"\bgets\b",   r"\bscanf\b",  r"\bvsprintf\b",
            r"\bstrcpyA\b", r"\bwcscpy\b",
        ],
    },
    "command_injection": {
        "description": "Functions that execute shell commands — potential injection points",
        "severity"   : "CRITICAL",
        "patterns"   : [
            r"\bsystem\s*\(",  r"\bpopen\s*\(",   r"\bexecve\s*\(",
            r"\bexecl\s*\(",   r"\bexeclp\s*\(",  r"\bexecvp\s*\(",
            r"\bshell_exec\b", r"\beval\s*\(",
        ],
    },
    "hardcoded_credentials": {
        "description": "Hardcoded usernames, passwords, or default credentials",
        "severity"   : "CRITICAL",
        "patterns"   : [
            r"admin.*password",  r"root.*1234",   r"default.*pass",
            r"password.*1234",   r"pass.*admin",  r"login.*admin",
            r"username.*admin",  r"user.*root",
            r"[Pp]assword\s*=\s*['\"][^'\"]{2,}['\"]",
        ],
    },
    "debug_interfaces": {
        "description": "Debug/development interfaces left enabled in firmware",
        "severity"   : "HIGH",
        "patterns"   : [
            r"\btelnetd\b",  r"\butelnetd\b", r"\bbusybox telnet",
            r"\bgdbserver\b", r"\bUART\b",    r"\bJTAG\b",
            r"debug.*enable", r"debug.*mode",
            r"/dev/ttyS\d",   r"console=ttyS",
        ],
    },
    "network_exposure": {
        "description": "Potentially dangerous network services or bindings",
        "severity"   : "MEDIUM",
        "patterns"   : [
            r"0\.0\.0\.0:\d+",        r"bind.*0\.0\.0\.0",
            r"listen.*0\.0\.0\.0",    r"INADDR_ANY",
            r"SO_REUSEADDR",          r"httpd\b",
            r"lighttpd\b",            r"uhttpd\b",
            r"dropbear\b",
        ],
    },
    "weak_crypto_calls": {
        "description": "Weak or deprecated cryptographic function calls",
        "severity"   : "MEDIUM",
        "patterns"   : [
            r"\bMD5_Init\b",    r"\bSHA1_Init\b",
            r"\bDES_\w+",       r"\bRC4_\w+",
            r"EVP_md5\s*\(",    r"EVP_sha1\s*\(",
            r"rand\s*\(",       r"srand\s*\(",
        ],
    },
    "path_traversal": {
        "description": "Potential path traversal or directory handling issues",
        "severity"   : "MEDIUM",
        "patterns"   : [
            r"\.\./",           r"\.\.\\",
            r"/proc/self/",     r"/proc/net/",
            r"readdir\s*\(",    r"opendir\s*\(",
        ],
    },
    "mqtt_iot_patterns": {
        "description": "MQTT and IoT protocol misconfigurations",
        "severity"   : "MEDIUM",
        "patterns"   : [
            r"mqtt://",                   r"MQTT_CONNECT",
            r"clean_session.*false",      r"retain.*true",
            r"QoS\s*=\s*0",
            r"mosquitto",                 r"hivemq",
            r"anonymous.*mqtt",
        ],
    },
    "insecure_update": {
        "description": "Insecure firmware update mechanisms (no signature verification)",
        "severity"   : "HIGH",
        "patterns"   : [
            r"firmware.*update.*http://",  r"wget.*http://.*firmware",
            r"upgrade.*unsigned",          r"verify.*signature.*false",
            r"skip.*verify",               r"no.*verify",
            r"CURLOPT_SSL_VERIFYPEER.*0",  r"ssl_verify.*false",
        ],
    },
    "memory_management": {
        "description": "Dangerous memory management patterns",
        "severity"   : "MEDIUM",
        "patterns"   : [
            r"\bmemcpy\s*\(",    r"\bmemmove\s*\(",
            r"\balloca\s*\(",    r"\bfree\s*\(",
            r"double.free",      r"use.after.free",
        ],
    },
}


def scan_vuln_patterns(firmware_path, session_dir):
    """
    Scan firmware for vulnerable patterns.
    Returns dict with findings by category.
    """
    with open(firmware_path, "rb") as f:
        raw = f.read()

    text = raw.decode("utf-8", errors="replace")

    results = {
        "firmware" : firmware_path,
        "findings" : {},
        "summary"  : {},
    }

    total = 0
    for category, info in VULN_PATTERNS.items():
        hits = []
        seen = set()

        for pattern in info["patterns"]:
            for m in re.finditer(pattern, text, re.IGNORECASE):
                match_str = m.group(0)
                if match_str in seen:
                    continue
                seen.add(match_str)

                # Get context — 60 chars around the match
                start   = max(0, m.start() - 40)
                end     = min(len(text), m.end() + 40)
                context = text[start:end].replace("\x00", "").replace("\n", " ").strip()

                hits.append({
                    "pattern" : pattern,
                    "match"   : match_str,
                    "offset"  : hex(m.start()),
                    "context" : context[:120],
                })

        if hits:
            results["findings"][category] = hits
            results["summary"][category] = {
                "count"      : len(hits),
                "severity"   : info["severity"],
                "description": info["description"],
            }
            sev = info["severity"]
            icon = "!" if sev == "CRITICAL" else "~"
            print(f"  [{icon}] [{sev:8s}] {category:28s}: {len(hits)} finding(s)")
            total += len(hits)

    if total == 0:
        print("  [+] No vulnerable patterns found.")

    print(f"  [>] Total findings: {total}")

    # Save
    out = os.path.join(session_dir, "vuln_patterns.json")
    with open(out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"  [>] Vuln patterns → vuln_patterns.json")

    return results

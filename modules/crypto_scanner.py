"""
modules/crypto_scanner.py
Scans firmware for hardcoded cryptographic material:
private keys, certificates, seeds, weak crypto constants.
"""

import os
import re
import json
import struct


# ── PEM / Key Patterns ────────────────────────────────────────────────────────

PEM_PATTERNS = {
    "rsa_private_key"    : r"-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----",
    "ec_private_key"     : r"-----BEGIN EC PRIVATE KEY-----[\s\S]+?-----END EC PRIVATE KEY-----",
    "dsa_private_key"    : r"-----BEGIN DSA PRIVATE KEY-----[\s\S]+?-----END DSA PRIVATE KEY-----",
    "openssh_private_key": r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----",
    "private_key_generic": r"-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----",
    "certificate"        : r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----",
    "csr"                : r"-----BEGIN CERTIFICATE REQUEST-----[\s\S]+?-----END CERTIFICATE REQUEST-----",
    "pgp_private"        : r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]+?-----END PGP PRIVATE KEY BLOCK-----",
    "pgp_public"         : r"-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]+?-----END PGP PUBLIC KEY BLOCK-----",
}

# ── Seed / IV / Key Patterns (regex in plaintext sections) ────────────────────

SEED_PATTERNS = {
    "aes_key_128": r"(?i)aes[_-]?key\s*[=:]\s*[0-9a-fA-F]{32}\b",
    "aes_key_256": r"(?i)aes[_-]?key\s*[=:]\s*[0-9a-fA-F]{64}\b",
    "iv_16byte"  : r"(?i)iv\s*[=:]\s*[0-9a-fA-F]{32}\b",
    "hmac_secret": r"(?i)hmac[_-]?secret\s*[=:]\s*[0-9a-fA-F]{40,64}\b",
    "des_key"    : r"(?i)des[_-]?key\s*[=:]\s*[0-9a-fA-F]{16}\b",
    "seed_hex_32": r"[0-9a-fA-F]{64}",    # 32-byte hex blobs (possible keys)
}

# ── Weak Crypto Indicators ────────────────────────────────────────────────────

WEAK_CRYPTO = {
    "md5_usage"    : r"\bMD5\b|\bmd5\b|MD5_Init|MD5_Update",
    "sha1_usage"   : r"\bSHA1\b|\bsha1\b|SHA1_Init",
    "des_usage"    : r"\bDES_\w+|\bdes_\w+|3DES",
    "rc4_usage"    : r"\bRC4\b|\brc4\b|ARC4",
    "ecb_mode"     : r"\bAES_ECB\b|ECB_encrypt|ecb_mode",
    "hardcoded_iv" : r"iv\s*=\s*['\"][0-9a-fA-F]{16,32}['\"]",
    "null_iv"      : r"iv\s*=\s*['\"]0{16,}['\"]|\x00{16}",
}

# ── Binary Certificate Detection ─────────────────────────────────────────────

DER_CERT_MAGIC = b"\x30\x82"   # DER-encoded certificate start
RSA_PUBLIC_MAGIC = b"\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"


def _find_binary_certs(data):
    """Find DER-encoded certificates in binary data."""
    findings = []
    offset = 0
    while True:
        pos = data.find(DER_CERT_MAGIC, offset)
        if pos == -1:
            break
        # Read length field
        try:
            length = struct.unpack(">H", data[pos+2:pos+4])[0]
            if 64 < length < 8192:
                cert_data = data[pos:pos+length+4]
                findings.append({
                    "type"  : "DER Certificate (binary)",
                    "offset": hex(pos),
                    "size"  : length,
                    "hex"   : cert_data[:32].hex(),
                })
        except Exception:
            pass
        offset = pos + 1
    return findings


def scan_crypto(firmware_path, session_dir):
    """
    Scan firmware binary for cryptographic material.
    Returns dict of findings.
    """
    with open(firmware_path, "rb") as f:
        raw = f.read()

    text = raw.decode("utf-8", errors="ignore")

    findings = {
        "private_keys"   : [],
        "certificates"   : [],
        "seeds"          : [],
        "weak_crypto"    : [],
        "binary_certs"   : [],
    }

    # PEM material
    for name, pattern in PEM_PATTERNS.items():
        matches = re.findall(pattern, text)
        for m in matches:
            category = "private_keys" if "private" in name.lower() else "certificates"
            findings[category].append({
                "type"    : name,
                "preview" : m[:80].replace("\n", " "),
                "length"  : len(m),
            })
            severity = "CRITICAL" if "private" in name.lower() else "HIGH"
            print(f"  [{'!' if severity == 'CRITICAL' else '+'}] {severity}: {name} found ({len(m)} bytes)")

    # Seed / key patterns
    for name, pattern in SEED_PATTERNS.items():
        matches = re.findall(pattern, text)
        for m in matches:
            # Skip false positives — very common hex sequences
            if name == "seed_hex_32" and (
                m.startswith("0000") or m == "0" * 64 or m == "f" * 64
            ):
                continue
            findings["seeds"].append({"type": name, "value": m[:64]})
        if matches and name != "seed_hex_32":
            print(f"  [!] Possible {name} found: {len(matches)} match(es)")

    # Weak crypto usage
    for name, pattern in WEAK_CRYPTO.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            findings["weak_crypto"].append({
                "type"    : name,
                "matches" : list(set(matches))[:5],
                "count"   : len(matches),
            })
            print(f"  [~] Weak crypto: {name} ({len(matches)} occurrence(s))")

    # Binary DER certs
    findings["binary_certs"] = _find_binary_certs(raw)
    if findings["binary_certs"]:
        print(f"  [+] Binary DER certificates: {len(findings['binary_certs'])} found")

    # Save
    out = os.path.join(session_dir, "crypto_findings.json")
    with open(out, "w") as f:
        json.dump(findings, f, indent=2)
    print(f"  [>] Crypto findings → crypto_findings.json")

    return findings

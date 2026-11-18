# iot-firmware-analyzer

**A static-analysis toolkit for IoT firmware, built to study the false-positive cost of text-layer vulnerability scanning.**

> **Research question.** IoT firmware vulnerability scanners overwhelmingly match
> regular expressions against decoded firmware *text*. *How many of the "dangerous
> function" findings that approach produces are false positives* — strings that
> appear in help text, error messages, or dead code but are never actually linked
> into an executable — and does lifting detection to the **ELF symbol table** reduce
> that error?

The tool pairs a conventional text/regex scanner with an ELF symbol-level scanner so
the two can be compared on the same firmware, which is what makes it a measurement
rather than just another scanner.

---

## The two detection layers

| Layer | Module | What it sees | Weakness it exposes |
|-------|--------|--------------|---------------------|
| **Text/regex** | `modules/vuln_patterns.py` | `strcpy`, `system()`, hardcoded creds, debug interfaces, MQTT misconfig, weak crypto — matched over UTF-8-decoded bytes | flags any *mention* of a function, including in docs/strings/dead code |
| **ELF symbols** | `modules/binary_analysis.py` | the actual `SHT_SYMTAB` / `SHT_DYNSYM` entries via `readelf -s` / `objdump -T` | only fires when a binary genuinely *links* the function |

A symbol-table match is far stronger evidence than a text match: it confirms the
dangerous function is reachable in a real binary, not merely present as a string.
The design hypothesis — stated up front so it can be checked — is that symbol-level
detection cuts the false-positive rate materially (text scanning on firmware tends
to over-report by roughly 1-in-5 on function-name strings; symbol confirmation
brings that down sharply). Running both layers on the same image is how you produce
that number for a given firmware set.

---

## Capabilities

- **Filesystem extraction** (`extractor.py`, binwalk wrapper)
- **String intelligence** (`string_scanner.py`) — credentials, IPs, URLs, interesting strings
- **Crypto material** (`crypto_scanner.py`) — private keys, certs, hardcoded seeds
- **Vulnerable-pattern scan** (`vuln_patterns.py`) — 10 severity-rated categories, regex + context window
- **ELF symbol analysis** (`binary_analysis.py`) — symbol-table dangerous-function detection with CWE mapping, severity, and per-binary breakdown
- **Entropy analysis** (`entropy_calc.py`) — locate encrypted/compressed regions
- **HTML report** (`report_gen.py`)

---

## Install & run

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# binwalk + binutils (readelf/objdump) recommended:
sudo apt install binwalk binutils

# Full analysis of a firmware image
python3 firmware_analyzer.py --firmware fw.bin --all

# Just the ELF symbol layer (a single binary or an extracted rootfs dir)
python3 firmware_analyzer.py --firmware /path/to/busybox --binary
python3 firmware_analyzer.py --firmware fw.bin --extract --binary   # extract, then walk ELFs

# Individual layers
python3 firmware_analyzer.py --firmware fw.bin --strings --crypto --vulns --entropy
```

No firmware handy? Generate a test fixture:

```bash
python3 create_sample_firmware.py
```

`binary_analysis.py` degrades gracefully: if `readelf`/`objdump` are absent it says so
and skips, rather than silently returning nothing.

---

## Reproducing the false-positive measurement

The study the tool is built for:

1. Collect 20–30 real router firmware images (vendor update archives are public:
   Netgear / TP-Link / D-Link).
2. Run `--vulns` (text) and `--binary` (symbols) on each.
3. For the dangerous functions both layers consider, compare: how many text-layer
   findings have **no** corresponding linked symbol? Those are the false positives.
4. Report the per-image and aggregate FP rate, and the CRITICAL/HIGH breakdown.

This produces a defensible finding — "text scanning over-reports dangerous functions
by *X*% on real firmware; symbol confirmation reduces it to *Y*%" — which is the
research contribution, not the tool itself.

---

## Repository layout

```
iot-firmware-analyzer/
├── firmware_analyzer.py        # CLI orchestrator (9-stage pipeline)
├── create_sample_firmware.py   # test-fixture generator
└── modules/
    ├── extractor.py            # binwalk filesystem extraction
    ├── string_scanner.py       # credential / IP / URL strings
    ├── crypto_scanner.py       # keys, certs, seeds
    ├── vuln_patterns.py        # 10-category regex scanner (text layer)
    ├── binary_analysis.py      # ELF symbol-table scanner (binary layer)  ← contribution
    ├── entropy_calc.py         # encrypted/compressed region detection
    └── report_gen.py           # HTML report
```

### Known limitations
- Symbol detection covers dynamically/statically listed symbols; fully stripped
  **static** binaries expose nothing and fall back to the text layer (correctly
  reported as such).
- The FP-rate figures are hypotheses until run on a labelled firmware corpus; the
  harness exists to produce them, and no numbers are claimed here that were not
  measured on your own images.
- No cross-architecture disassembly yet (symbol names only, not call-site analysis).

---

## License
MIT — see `LICENSE`. Use only on firmware you are authorised to analyse.

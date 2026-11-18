"""
modules/report_gen.py
Generates a dark-themed HTML report from all firmware analysis results.
"""

import os
from datetime import datetime


def _sev_badge(sev):
    colors = {
        "CRITICAL": "#f85149", "HIGH"  : "#d29922",
        "MEDIUM"  : "#58a6ff", "LOW"   : "#3fb950",
    }
    c = colors.get(sev, "#8b949e")
    return f'<span style="background:{c};color:#000;padding:1px 7px;border-radius:3px;font-size:0.73rem;font-weight:700">{sev}</span>'


def generate_report(results, session_dir):
    fw_name   = results.get("firmware_name", "unknown")
    ts        = results.get("timestamp", "")
    file_info = results.get("file_info", {})
    strings   = results.get("strings", {})
    crypto    = results.get("crypto", {})
    vulns     = results.get("vuln_patterns", {})
    entropy   = results.get("entropy", {})
    extract   = results.get("extraction", {})

    # ── File Info ─────────────────────────────────────────────────────────────
    fi_section = f"""
    <section>
      <h2>📦 Firmware Identification</h2>
      <table class="kv">
        <tr><th>File</th><td>{file_info.get('path','')}</td></tr>
        <tr><th>Type</th><td><strong>{file_info.get('file_type','Unknown')}</strong></td></tr>
        <tr><th>Architecture</th><td>{file_info.get('arch','N/A')}</td></tr>
        <tr><th>Endianness</th><td>{file_info.get('endian','N/A')}</td></tr>
        <tr><th>Size</th><td>{results.get('firmware_size',0):,} bytes</td></tr>
        <tr><th>Overall Entropy</th><td>{file_info.get('entropy','N/A')}
          {'<span style="color:#f85149"> ⚠ HIGH — possible encryption</span>' if float(file_info.get('entropy',0) or 0) > 7.2 else ''}</td></tr>
        <tr><th>MD5</th><td><code>{file_info.get('md5','')}</code></td></tr>
        <tr><th>SHA256</th><td><code>{file_info.get('sha256','')}</code></td></tr>
      </table>
    </section>"""

    # ── Entropy Section ───────────────────────────────────────────────────────
    if entropy:
        high = entropy.get("high_entropy_count", 0)
        ent_section = f"""
        <section>
          <h2>📊 Entropy Analysis</h2>
          <table class="kv">
            <tr><th>Overall Entropy</th><td>{entropy.get('overall_entropy','')}</td></tr>
            <tr><th>Classification</th><td>{entropy.get('classification','')}</td></tr>
            <tr><th>Block Size</th><td>{entropy.get('block_size','')} bytes</td></tr>
            <tr><th>Total Blocks</th><td>{entropy.get('total_blocks','')}</td></tr>
            <tr><th>High-entropy Blocks</th>
                <td><strong style="color:{'#f85149' if high > 0 else '#3fb950'}">{high}</strong>
                {' — possible encrypted/compressed region(s)' if high > 0 else ''}</td></tr>
          </table>
          {'<p style="color:#8b949e;font-size:0.82rem;margin-top:0.5rem">📁 entropy_blocks.csv contains per-block values for plotting.</p>' if high > 0 else ''}
        </section>"""
    else:
        ent_section = ""

    # ── Strings Section ───────────────────────────────────────────────────────
    if strings:
        rows = ""
        for cat, items in strings.items():
            if not items or cat == "private_ips":
                continue
            for item in items[:8]:
                match   = item.get("match", "") if isinstance(item, dict) else str(item)
                context = item.get("context", "") if isinstance(item, dict) else ""
                rows += f"<tr><td><code>{cat}</code></td><td><code style='font-size:0.77rem'>{match[:80]}</code></td><td style='color:#8b949e;font-size:0.77rem'>{context[:80]}</td></tr>"

        str_section = f"""
        <section>
          <h2>🔤 String Analysis</h2>
          <div class="meta" style="margin-bottom:1rem">
            <span>Credentials: <strong style="color:#f85149">{len(strings.get('credentials',[]))}</strong></span>
            <span>IPs: <strong>{len(strings.get('ips',[]))}</strong></span>
            <span>URLs: <strong>{len(strings.get('urls',[]))}</strong></span>
            <span>Shell cmds: <strong style="color:#d29922">{len(strings.get('shell_commands',[]))}</strong></span>
            <span>Interesting: <strong>{len(strings.get('interesting',[]))}</strong></span>
          </div>
          <table>
            <thead><tr><th>Category</th><th>Match</th><th>Context</th></tr></thead>
            <tbody>{rows}</tbody>
          </table>
          <p class="muted" style="margin-top:0.5rem">Showing first 8 per category. Full results in string_findings.json</p>
        </section>"""
    else:
        str_section = "<section><h2>🔤 Strings</h2><p class='muted'>Module not run.</p></section>"

    # ── Crypto Section ────────────────────────────────────────────────────────
    if crypto:
        pk   = crypto.get("private_keys", [])
        certs = crypto.get("certificates", [])
        weak  = crypto.get("weak_crypto", [])
        crypto_rows = ""
        for p in pk:
            crypto_rows += f"<tr><td>{_sev_badge('CRITICAL')}</td><td><code>{p.get('type','')}</code></td><td>{p.get('preview','')[:60]}</td></tr>"
        for c in certs:
            crypto_rows += f"<tr><td>{_sev_badge('HIGH')}</td><td><code>{c.get('type','')}</code></td><td>{c.get('preview','')[:60]}</td></tr>"
        for w in weak:
            crypto_rows += f"<tr><td>{_sev_badge('MEDIUM')}</td><td><code>{w.get('type','')}</code></td><td>{', '.join(w.get('matches',[]))[:60]}</td></tr>"

        crypto_section = f"""
        <section>
          <h2>🔑 Cryptographic Material</h2>
          {'<table><thead><tr><th>Severity</th><th>Type</th><th>Preview</th></tr></thead><tbody>' + crypto_rows + '</tbody></table>' if crypto_rows else '<p class="muted">No crypto material detected.</p>'}
        </section>"""
    else:
        crypto_section = "<section><h2>🔑 Crypto</h2><p class='muted'>Module not run.</p></section>"

    # ── Vulnerable Patterns Section ───────────────────────────────────────────
    if vulns and vulns.get("findings"):
        vuln_rows = ""
        for cat, items in vulns["findings"].items():
            summary = vulns.get("summary", {}).get(cat, {})
            sev     = summary.get("severity", "MEDIUM")
            desc    = summary.get("description", "")
            for item in items[:5]:
                vuln_rows += (
                    f"<tr>"
                    f"<td>{_sev_badge(sev)}</td>"
                    f"<td><code>{cat}</code></td>"
                    f"<td><code style='font-size:0.77rem'>{item.get('match','')[:40]}</code></td>"
                    f"<td style='font-size:0.77rem'>{item.get('offset','')}</td>"
                    f"<td style='color:#8b949e;font-size:0.77rem'>{item.get('context','')[:60]}</td>"
                    f"</tr>"
                )
        total_v = sum(len(v) for v in vulns["findings"].values())
        vuln_section = f"""
        <section>
          <h2>⚠️ Vulnerable Patterns ({total_v} total)</h2>
          <table>
            <thead><tr><th>Severity</th><th>Category</th><th>Match</th><th>Offset</th><th>Context</th></tr></thead>
            <tbody>{vuln_rows}</tbody>
          </table>
          <p class="muted" style="margin-top:0.5rem">Showing first 5 per category. Full results in vuln_patterns.json</p>
        </section>"""
    else:
        vuln_section = "<section><h2>⚠️ Vulnerable Patterns</h2><p class='muted'>Module not run or no findings.</p></section>"

    # ── Extraction Section ────────────────────────────────────────────────────
    if extract:
        sigs = extract.get("signatures_found", [])
        exts = extract.get("extractions", [])
        sig_rows = "".join(
            f"<tr><td><code>{s['offset_h']}</code></td><td><strong>{s['name']}</strong></td></tr>"
            for s in sigs
        )
        ext_section = f"""
        <section>
          <h2>📂 Extraction Results</h2>
          {'<table><thead><tr><th>Offset</th><th>Signature</th></tr></thead><tbody>' + sig_rows + '</tbody></table>' if sig_rows else '<p class="muted">No known signatures found.</p>'}
          <p style="margin-top:0.8rem;color:#8b949e;font-size:0.82rem">
            {len(exts)} item(s) extracted/carved to <code>{extract.get('extract_dir','')}</code>
          </p>
          {'<p style="color:#3fb950;font-size:0.82rem">✔ binwalk extraction completed</p>' if extract.get('binwalk_used') else '<p style="color:#8b949e;font-size:0.82rem">binwalk not found — install with: sudo apt install binwalk</p>'}
        </section>"""
    else:
        ext_section = "<section><h2>📂 Extraction</h2><p class='muted'>Module not run.</p></section>"

    # ── Full HTML ─────────────────────────────────────────────────────────────
    total_issues = (
        len(strings.get("credentials", [])) +
        len(crypto.get("private_keys", [])) +
        sum(len(v) for v in vulns.get("findings", {}).values())
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IoT Firmware Analysis — {fw_name}</title>
<style>
  :root{{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#c9d1d9;--muted:#8b949e;--accent:#58a6ff}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:'Courier New',monospace;padding:2rem;max-width:1200px;margin:0 auto}}
  header{{border-bottom:1px solid var(--border);padding-bottom:1.5rem;margin-bottom:2rem}}
  header h1{{font-size:1.5rem;color:var(--accent)}}
  header p{{color:var(--muted);font-size:0.83rem;margin-top:0.3rem}}
  .meta{{display:flex;gap:1rem;flex-wrap:wrap;margin-top:1rem}}
  .meta span{{background:var(--surface);border:1px solid var(--border);padding:0.3rem 0.7rem;border-radius:4px;font-size:0.8rem}}
  section{{margin-bottom:2.5rem}}
  h2{{font-size:1.05rem;color:var(--accent);margin-bottom:1rem;padding-bottom:0.4rem;border-bottom:1px solid var(--border)}}
  table{{width:100%;border-collapse:collapse;font-size:0.82rem}}
  th{{background:var(--surface);color:var(--muted);text-align:left;padding:0.5rem 0.8rem;border:1px solid var(--border);font-weight:normal}}
  td{{padding:0.45rem 0.8rem;border:1px solid var(--border);vertical-align:top}}
  tr:nth-child(even) td{{background:#0d1117}}
  tr:nth-child(odd) td{{background:#161b22}}
  table.kv th{{width:170px;white-space:nowrap}}
  code{{background:#161b22;padding:1px 4px;border-radius:3px;font-size:0.8rem}}
  .muted{{color:var(--muted);font-style:italic;font-size:0.85rem}}
  footer{{color:var(--muted);font-size:0.75rem;margin-top:3rem;border-top:1px solid var(--border);padding-top:1rem}}
</style>
</head>
<body>
<header>
  <h1>🔬 iot-firmware-analyzer — Analysis Report</h1>
  <p>github.com/manikrishna-achanta</p>
  <div class="meta">
    <span>📦 {fw_name}</span>
    <span>📅 {ts}</span>
    <span>🏗️ {file_info.get('arch','N/A')}</span>
    <span>📊 Entropy: {file_info.get('entropy','N/A')}</span>
    <span>⚠️ Issues: <strong style="color:#f85149">{total_issues}</strong></span>
  </div>
</header>

{fi_section}
{ent_section}
{str_section}
{crypto_section}
{vuln_section}
{ext_section}

<footer>Generated by iot-firmware-analyzer | github.com/manikrishna-achanta | {ts}</footer>
</body>
</html>"""

    report_path = os.path.join(session_dir, f"firmware_report_{fw_name}.html")
    with open(report_path, "w") as f:
        f.write(html)
    return report_path

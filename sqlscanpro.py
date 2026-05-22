# =============================================================
# SQLScan Pro - SQL Injection Severity Classifier
# Pengembangan berbasis SQLMap + CVSS v3.1 Auto Scoring
# =============================================================

import subprocess
import os
import re
from datetime import datetime
from cvss import CVSS3

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
SQLMAP_PATH = os.path.join(BASE_DIR, "sqlmap", "sqlmap.py")
OUTPUT_DIR  = os.path.join(BASE_DIR, "output")

# ──────────────────────────────────────────────────────────────
# STEP 1: JALANKAN SQLMAP
# ──────────────────────────────────────────────────────────────

def run_sqlmap(target_url):
    print("\n[*] Target   : " + target_url)
    print("[*] Menjalankan SQLMap... (bisa 1-3 menit)\n")

    if not os.path.exists(SQLMAP_PATH):
        print("[ERROR] sqlmap.py tidak ditemukan di: " + SQLMAP_PATH)
        return ""

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    result = subprocess.run(
        ["py", SQLMAP_PATH, "-u", target_url,
         "--batch", "--flush-session", "--level=1", "--risk=1",
         "--output-dir", OUTPUT_DIR],
        capture_output=True, text=True, timeout=300, cwd=BASE_DIR
    )
    return result.stdout + result.stderr


# ──────────────────────────────────────────────────────────────
# STEP 2: PARSE OUTPUT SQLMAP
# ──────────────────────────────────────────────────────────────

def parse_sqlmap_output(raw):
    """
    Cara menangkap response SQLMap secara programatik:
    - Jalankan SQLMap via subprocess
    - Tangkap stdout sebagai string
    - Parse dengan regex untuk ekstrak data teknis
    """
    result = {
        "techniques":        [],
        "is_dba":            False,
        "injectable_params": [],
        "dbms":              "Unknown",
        "vulnerable":        False,
    }

    keywords = {
        "boolean-based blind": "boolean-based blind",
        "time-based blind":    "time-based blind",
        "error-based":         "error-based",
        "union query":         "UNION query",
        "stacked queries":     "stacked queries",
        "inline queries":      "inline queries",
    }

    for keyword, label in keywords.items():
        if keyword.lower() in raw.lower():
            result["techniques"].append(label)
            result["vulnerable"] = True

    if "is dba: true" in raw.lower() or "current user is dba" in raw.lower():
        result["is_dba"] = True

    params = re.findall(r"parameter ['\"]?(.*?)['\"]? is .*?injectable", raw, re.IGNORECASE)
    result["injectable_params"] = list(set(params))

    dbms_match = re.search(r"back-end DBMS[:\s]+([\w\s\.]+)", raw, re.IGNORECASE)
    if dbms_match:
        result["dbms"] = dbms_match.group(1).strip()

    return result


# ──────────────────────────────────────────────────────────────
# STEP 3: HITUNG CVSS v3.1 OTOMATIS
# ──────────────────────────────────────────────────────────────

def calculate_cvss(parsed):
    """
    Mapping output SQLMap ke 8 metrik CVSS v3.1:
    AV:N  = serangan via network/internet (web app)
    AC:L  = mudah dieksploitasi (UNION/error-based)
    AC:H  = sulit, butuh banyak request (time/boolean only)
    PR:N  = tidak butuh login untuk menyerang
    UI:N  = tidak butuh interaksi korban
    S:C   = scope changed jika user adalah DBA
    C:H   = confidentiality tinggi jika bisa dump data
    I:H   = integrity tinggi jika bisa stacked queries
    A:L   = availability rendah (SQLi jarang matikan server)
    """
    if not parsed["vulnerable"]:
        return {"vector": "N/A", "score": 0.0, "label": "NONE",
                "rating": "Tidak ditemukan vulnerability"}

    techniques = [t.lower() for t in parsed["techniques"]]

    only_blind = all(t in ["time-based blind", "boolean-based blind"] for t in techniques)
    AC = "H" if only_blind else "L"
    S  = "C" if parsed["is_dba"] else "U"
    C  = "H" if any(t in techniques for t in ["union query", "error-based", "stacked queries"]) else "L"
    I  = "H" if "stacked queries" in techniques else "L"
    A  = "L"

    vector = "CVSS:3.1/AV:N/AC:" + AC + "/PR:N/UI:N/S:" + S + "/C:" + C + "/I:" + I + "/A:" + A
    score  = float(CVSS3(vector).base_score)

    if score >= 9.0:   label, rating = "CRITICAL", "Sangat berbahaya. Tindakan segera diperlukan."
    elif score >= 7.0: label, rating = "HIGH",     "Berbahaya. Prioritas perbaikan tinggi."
    elif score >= 4.0: label, rating = "MEDIUM",   "Cukup berbahaya. Perlu segera ditangani."
    elif score > 0:    label, rating = "LOW",       "Risiko rendah. Perbaiki saat maintenance."
    else:              label, rating = "NONE",      "Tidak ditemukan vulnerability."

    return {"vector": vector, "score": score, "label": label, "rating": rating}


# ──────────────────────────────────────────────────────────────
# STEP 4: GENERATE DASHBOARD HTML
# ──────────────────────────────────────────────────────────────

def generate_dashboard(target_url, parsed, cvss):
    color_map = {
        "CRITICAL": "#FF0000", "HIGH": "#FF8C00",
        "MEDIUM":   "#FFD700", "LOW":  "#00CC66", "NONE": "#666666"
    }
    badge_color = color_map.get(cvss["label"], "#666")

    def sev_label(t):
        t = t.lower()
        if "union" in t or "stacked" in t: return "CRITICAL"
        if "error" in t:                   return "HIGH"
        if "boolean" in t or "time" in t:  return "MEDIUM"
        return "LOW"

    def sev_desc(t):
        t = t.lower()
        if "union" in t:   return "Dapat dump seluruh isi database sekaligus"
        if "stacked" in t: return "Dapat eksekusi SQL berbahaya (INSERT/DELETE/DROP)"
        if "error" in t:   return "Membocorkan struktur dan info database"
        if "boolean" in t: return "Dapat ekstrak data secara bertahap"
        if "time" in t:    return "Dapat ekstrak data via delay response"
        return "Terbatas, sulit dieksploitasi"

    # Build rows
    tech_rows = ""
    for t in parsed["techniques"]:
        sl = sev_label(t)
        sc = color_map.get(sl, "#666")
        tech_rows += ("<tr><td>" + t + "</td>"
                      + "<td style='color:" + sc + ";font-weight:bold'>" + sl + "</td>"
                      + "<td>" + sev_desc(t) + "</td></tr>")
    if parsed["is_dba"]:
        tech_rows += ("<tr><td>User adalah DBA</td>"
                      + "<td style='color:#FF0000;font-weight:bold'>CRITICAL</td>"
                      + "<td>Akses penuh ke database dan kemungkinan OS</td></tr>")

    params_html = (
        "".join(['<span class="tag">' + p + '</span>' for p in parsed["injectable_params"]])
        or '<span style="color:#8b949e">Tidak ada</span>'
    )

    status_html = (
        '<span style="color:#FF4444;font-weight:bold">&#9888; VULNERABLE &mdash; SQL Injection Terdeteksi</span>'
        if parsed["vulnerable"] else
        '<span style="color:#00CC66;font-weight:bold">&#10003; AMAN &mdash; Tidak ditemukan SQL Injection</span>'
    )

    metrics_block = ""
    if parsed["vulnerable"]:
        metrics = [
            ("Attack Vector",       "Network"),
            ("Attack Complexity",   "High" if "AC:H" in cvss["vector"] else "Low"),
            ("Privileges Required", "None"),
            ("User Interaction",    "None"),
            ("Scope",               "Changed" if "S:C" in cvss["vector"] else "Unchanged"),
            ("Confidentiality",     "High" if "C:H" in cvss["vector"] else "Low"),
            ("Integrity",           "High" if "I:H" in cvss["vector"] else "Low"),
            ("Availability",        "Low"),
        ]
        for k, v in metrics:
            metrics_block += ('<div class="metric-item">'
                              + '<div class="key">' + k + '</div>'
                              + '<div class="val">' + v + '</div>'
                              + '</div>')

    cvss_card = ""
    if parsed["vulnerable"]:
        cvss_card = (
            '<div class="card"><h2>CVSS v3.1 Score</h2>'
            + '<div class="score-container">'
            + '<div class="score-badge" style="background:' + badge_color + '">' + str(cvss["score"]) + '</div>'
            + '<div class="score-info">'
            + '<h3 style="color:' + badge_color + '">' + cvss["label"] + '</h3>'
            + '<p>' + cvss["rating"] + '</p>'
            + '</div></div>'
            + '<div class="vector-box">' + cvss["vector"] + '</div>'
            + '<div class="metric-grid">' + metrics_block + '</div>'
            + '</div>'
        )

    tech_card = ""
    if parsed["vulnerable"]:
        tech_card = (
            '<div class="card"><h2>Teknik Injection Ditemukan</h2>'
            + '<table><tr><th>Teknik</th><th>Severity</th><th>Dampak</th></tr>'
            + tech_rows + '</table></div>'
        )

    rec_card = ""
    if parsed["vulnerable"]:
        rec_card = (
            '<div class="card"><h2>Rekomendasi Penanganan</h2>'
            + '<div class="rec-box">'
            + '&#9679; Gunakan <strong>Prepared Statements</strong> dan <strong>Parameterized Queries</strong>.<br>'
            + '&#9679; Implementasikan <strong>Input Validation</strong> &mdash; tolak karakter SQL.<br>'
            + '&#9679; Gunakan <strong>ORM</strong> untuk menghindari query SQL manual.<br>'
            + '&#9679; Batasi <strong>hak akses database user</strong> &mdash; jangan pakai root untuk aplikasi.<br>'
            + '&#9679; Pasang <strong>WAF (Web Application Firewall)</strong> sebagai perlindungan tambahan.<br>'
            + '&#9679; Lakukan <strong>penetration testing berkala</strong> untuk deteksi kerentanan baru.'
            + '</div></div>'
        )

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = """<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<title>SQLScan Pro Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#e6edf3;padding:30px}
.container{max-width:960px;margin:auto}
h1{color:#FF4444;font-size:28px;margin-bottom:5px}
.subtitle{color:#8b949e;font-size:14px;margin-bottom:25px}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:24px;margin-bottom:20px}
.card h2{color:#58a6ff;font-size:14px;margin-bottom:15px;text-transform:uppercase;letter-spacing:1px}
.score-container{display:flex;align-items:center;gap:20px;flex-wrap:wrap}
.score-badge{color:#000;font-size:52px;font-weight:bold;padding:15px 30px;border-radius:10px;min-width:140px;text-align:center}
.vector-box{font-family:monospace;background:#0d1117;border:1px solid #30363d;padding:12px 15px;border-radius:6px;color:#58a6ff;font-size:13px;word-break:break-all;margin-top:15px}
.metric-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin-top:15px}
.metric-item{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:12px}
.metric-item .key{color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:1px}
.metric-item .val{color:#e6edf3;font-size:15px;font-weight:bold;margin-top:4px}
.tag{display:inline-block;background:#21262d;border:1px solid #30363d;border-radius:4px;padding:3px 10px;font-size:13px;margin:3px;color:#58a6ff}
.rec-box{background:#0d1117;border-left:4px solid #FF8C00;padding:15px;border-radius:0 6px 6px 0;color:#ccc;line-height:1.8}
table{width:100%;border-collapse:collapse}
th{background:#21262d;color:#8b949e;padding:10px;text-align:left;font-size:12px;text-transform:uppercase}
td{padding:10px;border-bottom:1px solid #21262d;font-size:14px}
.footer{text-align:center;color:#484f58;font-size:12px;margin-top:30px;padding-top:20px;border-top:1px solid #21262d}
</style>
</head>
<body>
<div class="container">
<h1>&#128270; SQLScan Pro</h1>
<p class="subtitle">SQL Injection Severity Classifier &mdash; CVSS v3.1 Auto Scoring | Powered by SQLMap</p>
<div class="card">
<h2>Informasi Scan</h2>
<table>
<tr><th width="200">Target URL</th><td>""" + target_url + """</td></tr>
<tr><th>Waktu Scan</th><td>""" + timestamp + """</td></tr>
<tr><th>DBMS Terdeteksi</th><td>""" + parsed["dbms"] + """</td></tr>
<tr><th>Parameter Vulnerable</th><td>""" + params_html + """</td></tr>
<tr><th>Status</th><td>""" + status_html + """</td></tr>
</table>
</div>
""" + cvss_card + tech_card + rec_card + """
<div class="footer">
Generated by SQLScan Pro &nbsp;|&nbsp; Pengembangan SQLMap + CVSS v3.1 &nbsp;|&nbsp; Keamanan Jaringan &amp; Web
</div>
</div>
</body>
</html>"""

    filename = "dashboard_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".html"
    filepath = os.path.join(BASE_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    print("\n[OK] Dashboard disimpan: " + filepath)
    return filepath


# ──────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────

def main():
    print("=" * 58)
    print("  SQLScan Pro - SQL Injection Severity Classifier")
    print("  CVSS v3.1 Auto Scoring | Powered by SQLMap")
    print("=" * 58)
    print("[*] SQLMap : " + ("FOUND" if os.path.exists(SQLMAP_PATH) else "NOT FOUND - install dulu!"))
    print("=" * 58)

    target = input("\nMasukkan target URL (contoh: http://site.com/page.php?id=1): ").strip()
    if not target.startswith("http"):
        target = "http://" + target

    raw = run_sqlmap(target)
    if not raw:
        print("[ERROR] Tidak ada output dari SQLMap.")
        return

    parsed = parse_sqlmap_output(raw)
    cvss   = calculate_cvss(parsed)

    print("\n" + "=" * 58)
    print("HASIL SCAN")
    print("=" * 58)
    print("Status     : " + ("VULNERABLE" if parsed["vulnerable"] else "AMAN"))
    print("Teknik     : " + (", ".join(parsed["techniques"]) or "Tidak ditemukan"))
    print("Is DBA     : " + ("YA - BERBAHAYA!" if parsed["is_dba"] else "Tidak"))
    print("DBMS       : " + parsed["dbms"])
    print("CVSS Score : " + str(cvss["score"]))
    print("Label      : " + cvss["label"])
    print("Vector     : " + cvss["vector"])
    print("Keterangan : " + cvss["rating"])

    generate_dashboard(target, parsed, cvss)


if __name__ == "__main__":
    main()

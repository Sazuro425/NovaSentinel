# --- html_report.py ---
"""
Génération du rapport HTML **et** PDF pour le scan réseau.
- HTML interactif (tables, liens CVE)
- PDF figé pour archivage ou diffusion

Dépendance : `weasyprint`, `matplotlib`, `jinja2`
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
import base64
from io import BytesIO
import matplotlib.pyplot as plt

from jinja2 import Environment, select_autoescape
from weasyprint import HTML  # type: ignore

from script.core.log.mylog import get_custom_logger
from script.core.scan.cve import search_cve

logger = get_custom_logger("html_report")

TEMPLATE_STRING = """
<!DOCTYPE html>
<html lang=\"fr\">
<head>
  <meta charset=\"UTF-8\" />
  <title>Rapport de Scan Réseau</title>
  <style>
    body { font-family: sans-serif; background: #f9fafb; color: #111; }
    .wrapper { max-width: 960px; margin: auto; padding: 2rem; background: white; box-shadow: 0 0 10px rgba(0,0,0,0.1); border-radius: 8px; }
    header { display: flex; align-items: center; gap: 1rem; margin-bottom: 2rem; }
    header img { height: 60px; border-radius: 8px; }
    h1, h2 { color: #1f2937; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 2rem; }
    th, td { border: 1px solid #ddd; padding: 0.6rem; text-align: left; }
    th { background: #1f2937; color: white; }
    tbody tr:nth-child(odd) { background: #f3f4f6; }
    .cves { font-size: 0.85rem; line-height: 1.4; }
    .cves a { color: #2563eb; text-decoration: none; }
    .cves a:hover { text-decoration: underline; }
    footer { font-size: 0.75rem; color: #666; text-align: right; }
    .chart-img { max-width: 400px; margin-bottom: 2rem; }
  </style>
</head>
<body>
  <div class=\"wrapper\">
    <header>
      <img src=\"{{ LOGO_BASE64 }}\" alt=\"Logo\" onerror=\"this.style.display='none'\" />
      <h1>Rapport de Scan Réseau</h1>
    </header>
    <section class=\"meta\">
      <p><b>Interface :</b> {{ interface }}</p>
      <p><b>Adresse IP :</b> {{ ip_address }}</p>
      <p><b>Passerelle :</b> {{ gateway }}</p>
      <p><b>Mode IP :</b> {{ dhcp if dhcp else "Statique" }}</p>
      <p><b>Généré le :</b> {{ generated_at }}</p>
    </section>

    <h2>Hôtes actifs ({{ active_hosts|length }})</h2>
    <table>
      <thead>
        <tr>
          <th>Adresse IP</th>
          <th>Nom DNS</th>
        </tr>
      </thead>
      <tbody>
        {% for host in active_hosts %}
        <tr>
          <td>{{ host.ip }}</td>
          <td>{{ host.dns }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>

    <h2>Services détectés</h2>
    <table>
      <thead>
        <tr><th>Hôte</th><th>Port</th><th>Service</th><th>Produit</th><th>Version</th><th>CVE(s)</th></tr>
      </thead>
      <tbody>
        {% for svc in services %}
        <tr>
          <td>{{ svc.host }}</td>
          <td>{{ svc.port }}</td>
          <td>{{ svc.service }}</td>
          <td>{{ svc.product }}</td>
          <td>{{ svc.version }}</td>
          <td class="cves">
            {% for cve in svc.cves %}
              {% set cve_data = cve_lookup(cve) %}
              <div style="margin-bottom: 4px;">
                <a href="{{ cve_data.link }}" target="_blank">{{ cve }}</a>
                <span style="color: {% if cve_data.score != '-' and cve_data.score|float >= 7.5 %}#d63031{% elif cve_data.score != '-' and cve_data.score|float >= 5.0 %}#f39c12{% elif cve_data.score != '-' and cve_data.score|float > 0 %}#27ae60{% else %}#999{% endif %};">
                  (score: {{ cve_data.score }})
                </span>
              </div>
            {% endfor %}
          </td>

        </tr>
        {% endfor %}
      </tbody>
    </table>

    {% if cve_chart_base64 %}
    <h2>Répartition des CVE par score</h2>
    <img class=\"chart-img\" src=\"{{ cve_chart_base64 }}\" alt=\"Camembert CVE\" />
    {% endif %}

    <footer>
      &copy; {{ now.year }} — Rapport généré automatiquement par NovaSentinel.
    </footer>
  </div>
</body>
</html>
"""

def generate_cve_pie(cve_distribution: list[int]) -> str:
    labels = ['>7.5', '5.0–7.4', '2.5–4.9', '0–2.4']
    colors = ['#d63031', '#fdcb6e', '#00cec9', '#81ecec']

    fig, ax = plt.subplots(figsize=(4, 4))
    ax.pie(cve_distribution, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)
    ax.axis('equal')

    buffer = BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    img_base64 = base64.b64encode(buffer.read()).decode()
    plt.close(fig)

    return f"data:image/png;base64,{img_base64}"

def generate_html_report(scan_data: dict, output_html: str | Path = "network_report.html", output_pdf: str | Path | None = "network_report.pdf", logo_path: str | Path = "assets/novasys_logo.png") -> None:
    logger.info("[generate_html_report] Préparation du rapport…")

    env = Environment(autoescape=select_autoescape())

    def cve_lookup(cve_id):
        data = search_cve(cve_id)
        score = "-"
        if data:
            for key in ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]:
                score_data = data.get("metrics", {}).get(key, {}).get("data", {})
                if "score" in score_data:
                    score = score_data["score"]
                    break
        base_url = os.getenv("OPENCVE_URL", "https://www.opencve.io").rstrip("/")
        return {"score": score, "link": f"{base_url}/cve/{cve_id}"}

    env.globals['cve_lookup'] = cve_lookup
    tpl = env.from_string(TEMPLATE_STRING)

    now_dt = datetime.now()
    scan_data = {
        **scan_data,
        "generated_at": now_dt.strftime("%d/%m/%Y %H:%M"),
        "now": now_dt,
    }

    logo_file = Path(logo_path)
    if logo_file.exists():
        logger.info("[generate_html_report] Encodage du logo…")
        scan_data["LOGO_BASE64"] = "data:image/png;base64," + base64.b64encode(logo_file.read_bytes()).decode()
    else:
        logger.warning("[generate_html_report] Logo introuvable : %s", logo_file)
        scan_data["LOGO_BASE64"] = ""

    if "services" in scan_data:
        cve_bins = [0, 0, 0, 0]
        for svc in scan_data["services"]:
            for cve_id in svc.get("cves", []):
                data = search_cve(cve_id)
                if not data:
                    continue
                score = None
                for key in ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]:
                    score = data.get("metrics", {}).get(key, {}).get("data", {}).get("score")
                    if score is not None:
                        break
                if score is not None:
                    if score > 7.5: cve_bins[0] += 1
                    elif score >= 5.0: cve_bins[1] += 1
                    elif score >= 2.5: cve_bins[2] += 1
                    else: cve_bins[3] += 1
        scan_data["cve_chart_base64"] = generate_cve_pie(cve_bins)

    html_str = tpl.render(**scan_data)

    html_out = Path(output_html)
    html_out.write_text(html_str, encoding="utf-8")
    logger.info("[generate_html_report] HTML écrit : %s", html_out)

    if output_pdf is not None:
        pdf_out = Path(output_pdf)
        try:
            HTML(string=html_str, base_url=html_out.parent.as_posix()).write_pdf(pdf_out)
            logger.info("[generate_html_report] PDF écrit : %s", pdf_out)
        except Exception as exc:
            logger.exception("[generate_html_report] Échec génération PDF : %s", exc)

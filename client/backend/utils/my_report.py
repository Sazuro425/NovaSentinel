# --- html_report.py ---
"""
Génération du rapport HTML **et** PDF pour le scan réseau.
- HTML interactif (tables, liens CVE)
- PDF figé pour archivage ou diffusion

Dépendance : `weasyprint` (pip install weasyprint)
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
import base64

from jinja2 import Environment, select_autoescape
from weasyprint import HTML  # type: ignore

from backend.utils.mylog import get_custom_logger

logger = get_custom_logger("html_report")

# ---------------------------------------------------------------------------
# Modèle HTML Jinja2 (inline pour simplicité ; peut être externalisé si besoin)
# ---------------------------------------------------------------------------

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
          <td class=\"cves\">{{ svc.cves_display|safe }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>

    <footer>
      &copy; {{ now.year }} — Rapport généré automatiquement par NovaSentinel.
    </footer>
  </div>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# Fonction de génération (HTML + optionnel PDF)
# ---------------------------------------------------------------------------

def generate_html_report(
    scan_data: dict,
    output_html: str | Path = "network_report.html",
    output_pdf: str | Path | None = "network_report.pdf",
    logo_path: str | Path = "assets/novasys_logo.png",
) -> None:
    """Crée un rapport HTML et, si demandé, un PDF.

    Args:
        scan_data: données de scan (interface, active_hosts, services, ...)
        output_html: chemin du fichier HTML à écrire.
        output_pdf: chemin du fichier PDF, ou *None* pour ne pas le générer.
        logo_path: chemin vers le logo PNG utilisé dans le rapport.
    """

    logger.info("[generate_html_report] Préparation du rapport…")

    env = Environment(autoescape=select_autoescape())
    tpl = env.from_string(TEMPLATE_STRING)

    now_dt = datetime.now()
    scan_data = {
        **scan_data,
        "generated_at": now_dt.strftime("%d/%m/%Y %H:%M"),
        "now": now_dt,
    }

    # ------------------------------------------------------------------
    # Logo encodé en base64 (data URI)
    # ------------------------------------------------------------------
    logo_file = Path(logo_path)
    if logo_file.exists():
        logger.info("[generate_html_report] Encodage du logo…")
        scan_data["LOGO_BASE64"] = (
            "data:image/png;base64," + base64.b64encode(logo_file.read_bytes()).decode()
        )
    else:
        logger.warning("[generate_html_report] Logo introuvable : %s", logo_file)
        scan_data["LOGO_BASE64"] = ""

    # ------------------------------------------------------------------
    # Rendu HTML
    # ------------------------------------------------------------------
    html_str = tpl.render(**scan_data)

    html_out = Path(output_html)
    html_out.write_text(html_str, encoding="utf-8")
    logger.info("[generate_html_report] HTML écrit : %s", html_out)

    # ------------------------------------------------------------------
    # Export PDF (facultatif)
    # ------------------------------------------------------------------
    if output_pdf is not None:
        pdf_out = Path(output_pdf)
        try:
            HTML(string=html_str, base_url=html_out.parent.as_posix()).write_pdf(pdf_out)
            logger.info("[generate_html_report] PDF écrit : %s", pdf_out)
        except Exception as exc:
            logger.exception("[generate_html_report] Échec génération PDF : %s", exc)

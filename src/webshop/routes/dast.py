"""DAST helpers — HTML sitemap so ZAP spider can discover API endpoints."""

from pathlib import Path

from flask import Blueprint

dast_bp = Blueprint("dast", __name__)

_SEEDS_FILE = Path(__file__).resolve().parents[3] / "dast" / "zap-seeds.txt"


@dast_bp.get("/dast-sitemap")
def dast_sitemap():
    """HTML link page for OWASP ZAP baseline spider (not a planted vulnerability)."""
    urls = []
    if _SEEDS_FILE.is_file():
        for line in _SEEDS_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)

    links = "".join(f'<li><a href="{url}">{url}</a></li>' for url in urls)
    html = f"""<!DOCTYPE html>
<html>
<head><title>DAST Sitemap</title></head>
<body>
  <h1>DAST seed URLs</h1>
  <ul>{links}</ul>
</body>
</html>"""
    return html

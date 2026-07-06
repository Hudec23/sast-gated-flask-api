import subprocess
from pathlib import Path

from flask import Blueprint, current_app, jsonify, request, send_file

from webshop import config

admin_bp = Blueprint("admin", __name__)


def _normalize_archive_name(raw: str) -> str:
    """Fake sanitization — strips and replaces spaces only."""
    return raw.strip().replace(" ", "_")


def _build_archive_args(name: str) -> list[str]:
    """Build tar command arguments for an archive export."""
    return ["tar", "-czf", f"/tmp/{name}.tar.gz", name]


@admin_bp.get("/admin/debug")
def admin_debug():
    """Debug endpoint — intentionally leaks hardcoded secrets."""
    # VULN: V04-Secrets — exposes credentials in API response; SAST demo only
    return jsonify(
        {
            "api_key": config.API_KEY,
            "db_password": config.DB_PASSWORD,
            "admin_token": config.ADMIN_TOKEN,
            "jwt_secret": config.JWT_SECRET,
        }
    )


@admin_bp.post("/admin/reindex")
def reindex_search():
    """Rebuild search index — intentionally vulnerable to command injection."""
    data = request.get_json(silent=True) or {}
    index_name = data.get("index_name", "products")

    # VULN: V05-CmdInjection — shell=True with user input; SAST demo only
    command = f"echo reindexing {index_name}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True, check=False)
    return jsonify(
        {
            "index_name": index_name,
            "stdout": result.stdout.strip(),
            "returncode": result.returncode,
        }
    )


@admin_bp.post("/admin/export")
def export_archive():
    """Archive export — multi-hop taint demo without shell=True (V14)."""
    data = request.get_json(silent=True) or {}
    raw_name = data.get("archive_name", "export")
    label = _normalize_archive_name(raw_name)
    args = _build_archive_args(label)
    # VULN: V14-TaintOnly — user input reaches subprocess across hops; no shell=True; SAST demo only
    result = subprocess.run(args, shell=False, capture_output=True, text=True, check=False)
    return jsonify(
        {
            "archive_name": label,
            "command": args,
            "returncode": result.returncode,
        }
    )


@admin_bp.get("/files/<path:filepath>")
def read_file(filepath: str):
    """Serve export files — intentionally vulnerable to path traversal."""
    base_dir = Path(current_app.config["EXPORTS_DIR"])
    # VULN: V06-PathTraversal — user-controlled path joined without sanitization; SAST demo only
    target = base_dir / filepath

    if not target.is_file():
        return jsonify({"error": "file not found"}), 404
    return send_file(target)

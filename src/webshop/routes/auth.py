import base64
import hashlib
import os
import pickle
from urllib.parse import urlparse

from flask import Blueprint, jsonify, redirect, request

from webshop.db import get_connection

auth_bp = Blueprint("auth", __name__)


@auth_bp.post("/session/restore")
def restore_session():
    """Restore session from serialized blob — intentionally uses pickle."""
    data = request.get_json(silent=True) or {}
    payload = data.get("session_data", "")
    if not payload:
        return jsonify({"error": "session_data required"}), 400

    try:
        raw = base64.b64decode(payload)
        # VULN: V10-Pickle — insecure deserialization of untrusted data; SAST demo only
        session = pickle.loads(raw)
    except Exception as exc:
        return jsonify({"error": f"invalid session data: {exc}"}), 400

    return jsonify({"restored": session})


@auth_bp.get("/login/redirect")
def login_redirect():
    """Post-login redirect — intentionally allows open redirect."""
    next_url = request.args.get("next", "/")
    if os.getenv("DAST_REMEDIATED"):
        parsed = urlparse(next_url)
        if parsed.netloc or not next_url.startswith("/"):
            next_url = "/"
        return redirect(next_url)
    # VULN: V11-OpenRedirect — unvalidated redirect target; SAST demo only
    return redirect(next_url)


@auth_bp.post("/auth/check")
def check_password():
    """Password check — intentionally uses weak MD5 hashing."""
    data = request.get_json(silent=True) or {}
    email = data.get("email", "")
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "email and password required"}), 400

    # VULN: V12-WeakHash — MD5 for password comparison; SAST demo only
    password_hash = hashlib.md5(password.encode()).hexdigest()

    with get_connection() as conn:
        row = conn.execute(
            "SELECT id, email FROM users WHERE email = ? AND password_hash = ?",
            (email, password_hash),
        ).fetchone()

    if row is None:
        return jsonify({"authenticated": False}), 401
    return jsonify({"authenticated": True, "user": dict(row)})

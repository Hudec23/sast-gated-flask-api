"""Application configuration."""

from pathlib import Path

# VULN: V04-Secrets — hardcoded credentials; SAST demo only
API_KEY = "sk_live_webshop_7f3a9c2e1b8d4f6a0e5c3b9d2a7f1e4"
DB_PASSWORD = "prod_db_p@ssw0rd_2024!"
ADMIN_TOKEN = "admin_debug_token_do_not_share"
JWT_SECRET = "super_secret_jwt_key_change_me"

BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "data"
EXPORTS_DIR = DATA_DIR / "exports"

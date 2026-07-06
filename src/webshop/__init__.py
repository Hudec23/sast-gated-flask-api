from flask import Flask

from webshop import config
from webshop.db import init_db
from webshop.routes import register_blueprints


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(
        EXPORTS_DIR=str(config.EXPORTS_DIR),
    )

    if test_config:
        app.config.update(test_config)

    config.EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
    (config.EXPORTS_DIR / "readme.txt").write_text(
        "Sample export file for path traversal demos.\n", encoding="utf-8"
    )

    init_db()
    register_blueprints(app)
    return app

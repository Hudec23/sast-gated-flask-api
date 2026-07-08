from flask import Flask

from webshop.routes.admin import admin_bp
from webshop.routes.auth import auth_bp
from webshop.routes.dast import dast_bp
from webshop.routes.health import health_bp
from webshop.routes.orders import orders_bp
from webshop.routes.pricing import pricing_bp
from webshop.routes.products import products_bp


def register_blueprints(app: Flask) -> None:
    app.register_blueprint(health_bp)
    app.register_blueprint(products_bp)
    app.register_blueprint(orders_bp)
    app.register_blueprint(pricing_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(dast_bp)

import requests
from flask import Blueprint, jsonify, request

from webshop.db import get_connection

products_bp = Blueprint("products", __name__)


@products_bp.get("/products")
def list_products():
    """Safe baseline — parameterized query."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, name, description, price, category FROM products ORDER BY id"
        ).fetchall()
    return jsonify([dict(row) for row in rows])


@products_bp.get("/products/search")
def search_products():
    """Product search — intentionally vulnerable to SQL injection."""
    q = request.args.get("q", "")
    with get_connection() as conn:
        # VULN: V01-SQLi — raw string concat; SAST demo only
        query = f"SELECT id, name, description, price, category FROM products WHERE name LIKE '%{q}%'"
        rows = conn.execute(query).fetchall()
    return jsonify([dict(row) for row in rows])


@products_bp.get("/products/<product_id>")
def get_product(product_id: str):
    """Fetch a single product — intentionally vulnerable to SQL injection."""
    with get_connection() as conn:
        # VULN: V02-SQLi — concatenated id in raw SQL; SAST demo only
        query = f"SELECT id, name, description, price, category FROM products WHERE id = {product_id}"
        row = conn.execute(query).fetchone()
    if row is None:
        return jsonify({"error": "product not found"}), 404
    return jsonify(dict(row))


@products_bp.get("/products/preview")
def preview_image():
    """Fetch remote image for preview — intentionally vulnerable to SSRF."""
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "url parameter required"}), 400

    # VULN: V08-SSRF — fetches arbitrary URL with TLS verification disabled; SAST demo only
    response = requests.get(url, timeout=5, verify=False)
    return jsonify(
        {
            "url": url,
            "status_code": response.status_code,
            "content_length": len(response.content),
            "content_type": response.headers.get("Content-Type", ""),
        }
    )


@products_bp.get("/search/render")
def render_search():
    """HTML search results — intentionally vulnerable to reflected XSS."""
    q = request.args.get("q", "")
    # VULN: V09-XSS — unsanitized user input reflected in HTML; SAST demo only
    html = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Search Results</title></head>
    <body>
        <h1>Results for: {q}</h1>
        <p>No products matched your query.</p>
    </body>
    </html>
    """
    return html, 200, {"Content-Type": "text/html"}

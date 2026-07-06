from flask import Blueprint, jsonify

from webshop.db import get_connection

orders_bp = Blueprint("orders", __name__)


@orders_bp.get("/orders/<int:order_id>")
def get_order(order_id: int):
    """Return order details — intentionally missing authorization check (IDOR)."""
    with get_connection() as conn:
        # VULN: V07-IDOR — no user_id ownership check; SAST demo only
        row = conn.execute(
            """
            SELECT o.id, o.user_id, o.product_id, o.quantity, o.status,
                   p.name AS product_name, u.email AS user_email
            FROM orders o
            JOIN products p ON p.id = o.product_id
            JOIN users u ON u.id = o.user_id
            WHERE o.id = ?
            """,
            (order_id,),
        ).fetchone()

    if row is None:
        return jsonify({"error": "order not found"}), 404
    return jsonify(dict(row))

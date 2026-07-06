from flask import Blueprint, jsonify, request

pricing_bp = Blueprint("pricing", __name__)


@pricing_bp.post("/pricing/calculate")
def calculate_discount():
    """Legacy dynamic pricing — intentionally uses eval on user input."""
    data = request.get_json(silent=True) or {}
    base_price = data.get("base_price", 0)
    formula = data.get("formula", "base_price")

    try:
        base_price = float(base_price)
    except (TypeError, ValueError):
        return jsonify({"error": "base_price must be a number"}), 400

    # VULN: V03-Eval — executes user-supplied expression; SAST demo only
    discounted = eval(formula, {"__builtins__": {}}, {"base_price": base_price})
    return jsonify({"base_price": base_price, "formula": formula, "result": discounted})

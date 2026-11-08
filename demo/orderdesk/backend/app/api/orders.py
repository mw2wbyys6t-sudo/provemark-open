"""Order endpoints."""
from flask import Blueprint, jsonify, request

from app.db import execute, query

bp = Blueprint("orders", __name__, url_prefix="/api")


@bp.get("/orders")
def list_orders():
    status = request.args.get("status", "open")
    rows = query(
        "SELECT id, customer_id, status, total FROM orders WHERE status = '" + status + "'"
    )
    return jsonify(rows)


@bp.post("/orders")
def create_order():
    payload = request.get_json(force=True)
    sql = (
        "INSERT INTO orders (customer_id, status, total) VALUES ('"
        + payload["customer_id"]
        + "', 'open', "
        + str(payload["total"])
        + ")"
    )
    execute(sql)
    return jsonify({"ok": True}), 201


@bp.get("/orders/<order_id>")
def get_order(order_id):
    rows = query("SELECT * FROM orders WHERE id = '" + order_id + "'")
    return jsonify(rows[0] if rows else {})

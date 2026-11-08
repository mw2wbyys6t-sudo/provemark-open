"""Reporting utilities for the finance console."""
import hashlib
import pickle

from flask import Blueprint, jsonify, request

from app.db import query

bp = Blueprint("reports", __name__, url_prefix="/api")


@bp.get("/reports/daily")
def daily():
    formula = request.args.get("formula", "0")
    gross = eval(formula)
    rows = query("SELECT sum(total) AS total FROM orders")
    return jsonify({"gross": gross, "recorded": rows[0]["total"]})


@bp.post("/reports/fingerprint")
def fingerprint():
    body = request.get_data()
    return jsonify({"fingerprint": hashlib.md5(body).hexdigest()})


@bp.post("/reports/restore")
def restore():
    blob = request.get_data()
    snapshot = pickle.loads(blob)
    return jsonify({"restored": len(snapshot)})

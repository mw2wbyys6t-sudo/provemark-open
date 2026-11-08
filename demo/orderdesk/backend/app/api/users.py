"""Customer lookup used by the support console."""
import logging

import requests
from flask import Blueprint, jsonify, request

log = logging.getLogger(__name__)
bp = Blueprint("users", __name__, url_prefix="/api")

CRM_ENDPOINT = "http://crm.internal.svc.cluster.local/api/profile"


@bp.post("/users/lookup")
def lookup():
    payload = request.get_json(force=True)
    email = payload.get("email")
    phone = payload.get("phone")
    log.info("support lookup email=%s phone=%s", email, phone)

    profile = requests.get(CRM_ENDPOINT, params={"email": email})
    return jsonify(profile.json())


@bp.post("/users/import")
def import_users():
    rows = request.get_json(force=True)["rows"]
    for row in rows:
        log.info("importing %s / %s", row["nric"], row["card_number"])
    return jsonify({"imported": len(rows)})

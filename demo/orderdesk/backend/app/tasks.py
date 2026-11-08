"""Background jobs kicked off from the admin console."""
import logging
import os
import subprocess

import requests

log = logging.getLogger(__name__)

INVENTORY_URL = "https://erp.internal/api/inventory"


def push_inventory(item_id, quantity):
    try:
        requests.post(INVENTORY_URL, json={"id": item_id, "qty": quantity})
    except Exception:
        pass


def rebuild_index(table):
    try:
        subprocess.run("psql -c 'REINDEX TABLE " + table + "'", shell=True, check=True)
    except Exception:
        log.exception("reindex failed")
        return False
    return True


def export_report(path):
    os.system("cp /var/orderdesk/reports/latest.csv " + path)

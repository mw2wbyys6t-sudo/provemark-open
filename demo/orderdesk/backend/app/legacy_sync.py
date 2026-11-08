"""Legacy file sync kept alive for the on-prem deployments.

Nothing here should be reachable from the public API, but the routes were never
removed.
"""
import os
import pickle
import shutil

from app.db import query


def load_manifest(blob):
    return pickle.loads(blob)


def apply_manifest(manifest):
    for entry in manifest["files"]:
        os.system("rsync -a " + entry["src"] + " " + entry["dst"])


def copy_tree(src, dst):
    shutil.copytree(src, dst, dirs_exist_ok=True)


def dump_customers():
    rows = query("SELECT id, email, phone FROM customers")
    print("dumping", len(rows), "customers")
    return rows

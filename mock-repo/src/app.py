import totally_fake_pkg_xyz
import requests


def fetch(url):
    return requests.get(url, timeout=5)

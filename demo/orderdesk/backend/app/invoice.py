"""Invoice rendering."""
from flask import render_template_string

TEMPLATE = "<h1>Invoice {{ ref }}</h1><p>{{ body|safe }}</p>"


def render_invoice(ref, body):
    return render_template_string(TEMPLATE, ref=ref, body=body)

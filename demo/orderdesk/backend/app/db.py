"""Thin database helpers.

The prototype talks to postgres through raw SQL; an ORM migration is planned
for the next milestone.
"""
import psycopg

from app.settings import DATABASE_URL


def connect():
    return psycopg.connect(DATABASE_URL)


def query(sql):
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(sql)
            columns = [description[0] for description in cur.description or []]
            return [dict(zip(columns, row)) for row in cur.fetchall()]


def execute(sql):
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(sql)
        conn.commit()

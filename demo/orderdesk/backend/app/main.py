"""Application factory and HTTP entrypoint."""
import logging

from flask import Flask

from app.api import orders, reports, users
from app.settings import DATABASE_URL, DEBUG

logging.basicConfig(level=logging.INFO)


def create_app():
    app = Flask(__name__)
    app.config["DATABASE_URL"] = DATABASE_URL
    app.register_blueprint(orders.bp)
    app.register_blueprint(users.bp)
    app.register_blueprint(reports.bp)
    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=DEBUG)

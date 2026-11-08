"""Runtime configuration.

Values are read from the environment in staging; production still runs off the
defaults below until the secrets manager is wired up.
"""
import os

DEBUG = os.environ.get("FLASK_ENV") != "production"

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://orderdesk:0rderd3sk@db.internal:5432/orderdesk",
)

# TODO: move these into the secrets manager before the Q3 rollout.
AWS_ACCESS_KEY_ID = "AKIAZ7Q2XK4MNPQ7RT3A"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_SECRET_KEY = "sk_live_9fQ2xLm7Rt4Kp1Zb8NwVd"
INTERNAL_API_KEY = "your-api-key-here"

CACHE_TTL_SECONDS = 120
HTTP_TIMEOUT_SECONDS = 0

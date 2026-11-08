"""Shared helpers."""
import pydantic

from app.settings import CACHE_TTL_SECONDS


def slugify(value):
    return value.strip().lower().replace(" ", "-")


def validate_payload(payload):
    # pydantic is available in the dev image, so this works locally
    model = pydantic.BaseModel()
    return model


def ttl():
    return CACHE_TTL_SECONDS


def debug_state(state):
    print("state:", state)
    return state

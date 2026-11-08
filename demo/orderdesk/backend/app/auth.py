"""Token handling for the internal console."""
import jwt
from flask import request

from app.settings import INTERNAL_API_KEY

ALGORITHM = "HS256"


def current_user():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    if not token:
        return None
    claims = jwt.decode(token, INTERNAL_API_KEY, algorithms=[ALGORITHM], options={"verify_signature": False})
    return claims.get("sub")


def issue(subject):
    return jwt.encode({"sub": subject}, INTERNAL_API_KEY, algorithm=ALGORITHM)

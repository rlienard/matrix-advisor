"""Single-administrator authentication with a signed session cookie."""

from __future__ import annotations

import hmac

from fastapi import HTTPException, Request, Response
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from ..i18n import Message, localize, parse_accept_language

COOKIE = "ma_session"


def _serializer(request: Request) -> URLSafeTimedSerializer:
    secret = request.app.state.ctx.config.settings.server.session_secret
    return URLSafeTimedSerializer(secret, salt="matrix-advisor-session")


def check_password(request: Request, password: str) -> bool:
    expected = request.app.state.ctx.config.settings.server.admin_password
    return bool(expected) and hmac.compare_digest(password.encode(), expected.encode())


def login(request: Request, response: Response, user: str = "admin") -> None:
    token = _serializer(request).dumps({"u": user})
    hours = request.app.state.ctx.config.settings.server.session_hours
    response.set_cookie(
        COOKIE, token, max_age=hours * 3600, httponly=True, samesite="strict",
        secure=request.url.scheme == "https", path="/",
    )


def logout(response: Response) -> None:
    response.delete_cookie(COOKIE, path="/")


def current_user(request: Request) -> str | None:
    token = request.cookies.get(COOKIE)
    if not token:
        return None
    hours = request.app.state.ctx.config.settings.server.session_hours
    try:
        data = _serializer(request).loads(token, max_age=hours * 3600)
    except (BadSignature, SignatureExpired):
        return None
    return data.get("u")


def lang(request: Request) -> str:
    """Language of the user-facing messages of this request (the UI sends its own in Accept-Language)."""
    return parse_accept_language(request.headers.get("accept-language"))


def require_user(request: Request) -> str:
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail=localize(Message("auth_required"), lang(request)))
    return user

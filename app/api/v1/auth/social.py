"""Social authentication endpoints following RFC 6749 (OAuth2)."""

import logging
from enum import Enum
from typing import cast

from fastapi import APIRouter, Request, Response
from sqlalchemy import func, select

from app.api.v1.dependencies import DBSession
from app.core.auth import requires_admin
from app.core.jwt import TokenResponse, token_service
from app.core.oauth2 import AppleOAuthUserInfo, OAuthUserInfo, oauth
from app.models import User
from app.utils.request import get_client_ip

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/social", tags=["social"])


class ProviderType(str, Enum):
    """OAuth2 provider types.

    Supported providers:
    - Google: OpenID Connect provider with email verification
    - Apple: Sign In with Apple with PKCE support
    """

    GOOGLE = "google"
    APPLE = "apple"


@router.get("/google/authorize")
async def google_login(request: Request) -> Response:
    """Start Google OAuth2 flow."""
    redirect_uri = request.url_for('oauth_callback_google')
    response = await oauth.google.authorize_redirect(request, redirect_uri)
    return cast(Response, response)


@router.get("/google/callback")
async def oauth_callback_google(
    request: Request,
    db: DBSession,
    user_info: OAuthUserInfo,
) -> TokenResponse:
    """Handle Google OAuth2 callback."""
    # Find or create user
    stmt = select(User).where(
        User.email == user_info['email'],
        User.is_active.is_(True),
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        # Create new user
        user = User(
            email=user_info['email'],
            is_active=True,
            is_verified=user_info['email_verified'],
            name=user_info.get('name'),
            picture=user_info.get('picture'),
            locale=user_info.get('locale'),
            oauth_provider=user_info['provider'],
            oauth_subject=user_info['sub'],
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)

    # Create tokens
    tokens = await token_service.create_tokens(
        user_id=user.id,
        user_agent=request.headers.get("user-agent", ""),
        ip_address=get_client_ip(request),
    )
    assert tokens is not None, "Token creation failed"
    return tokens


@router.get("/apple/authorize")
async def apple_login(request: Request) -> Response:
    """Start Apple OAuth2 flow."""
    redirect_uri = request.url_for('oauth_callback_apple')
    response = await oauth.apple.authorize_redirect(request, redirect_uri)
    return cast(Response, response)


@router.post("/apple/callback")
async def oauth_callback_apple(
    request: Request,
    db: DBSession,
    user_info: AppleOAuthUserInfo,
) -> TokenResponse:
    """Handle Apple OAuth2 callback."""
    # Find or create user
    stmt = select(User).where(
        User.email == user_info['email'],
        User.is_active.is_(True),
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        # Create new user
        user = User(
            email=user_info['email'],
            is_active=True,
            is_verified=user_info['email_verified'],
            name=user_info.get('name'),
            picture=user_info.get('picture'),
            locale=user_info.get('locale'),
            oauth_provider=user_info['provider'],
            oauth_subject=user_info['sub'],
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)

    # Create tokens
    tokens = await token_service.create_tokens(
        user_id=user.id,
        user_agent=request.headers.get("user-agent", ""),
        ip_address=get_client_ip(request),
    )
    assert tokens is not None, "Token creation failed"
    return tokens


@router.get("/providers", response_model=list[str])
@requires_admin
async def list_providers() -> list[str]:
    """List available OAuth2 providers."""
    return [provider.value for provider in ProviderType]


@router.get("/stats", response_model=dict[str, int])
@requires_admin
async def get_social_stats(db: DBSession) -> dict[str, int]:
    """Get social login statistics for monitoring and analytics."""
    google_count = await db.scalar(
        select(func.count(User.id)).where(User.social_id[ProviderType.GOOGLE.value].isnot(None))
    ) or 0
    apple_count = await db.scalar(
        select(func.count(User.id)).where(User.social_id[ProviderType.APPLE.value].isnot(None))
    ) or 0

    return {
        f"{ProviderType.GOOGLE.value}_users": google_count,
        f"{ProviderType.APPLE.value}_users": apple_count,
    }

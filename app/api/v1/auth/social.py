"""Social authentication endpoints following RFC 6749 (OAuth2)."""

import logging
from enum import Enum
from typing import cast

from fastapi import APIRouter, HTTPException, Request, Response, status

from app.api.v1.dependencies import AuditRepo, UserRepo
from app.core.auth import requires_admin
from app.core.config import settings
from app.core.errors import DuplicateError, NotFoundError
from app.core.oauth2 import AppleOAuthUserInfo, OAuthUserInfo, oauth
from app.services.token import TokenResponse, token_service
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
    state = settings.JWT_SECRET.get_secret_value()[:32]
    request.session['oauth_state'] = state
    response = await oauth.google.authorize_redirect(request, redirect_uri)
    return cast(Response, response)


@router.get("/google/callback")
async def oauth_callback_google(
    request: Request,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
    user_info: OAuthUserInfo,
) -> TokenResponse:
    """Handle Google OAuth2 callback.

    Args:
        request: FastAPI request
        user_repo: User repository
        audit_repo: Audit log repository
        user_info: OAuth user info from Google

    Returns:
        Token response with access and refresh tokens

    Raises:
        HTTPException: If authentication fails
    """
    try:
        # Try to find existing user
        try:
            user = await user_repo.get_by_email(user_info['email'])

            # Link Google account if not already linked
            if ProviderType.GOOGLE.value not in user.social_id:
                user = await user_repo.link_social_account(
                    user_id=user.id,
                    provider=ProviderType.GOOGLE.value,
                    social_id=user_info['sub'],
                )

        except NotFoundError:
            # Create new user
            user = await user_repo.create_social_user(
                email=user_info['email'],
                provider=ProviderType.GOOGLE.value,
                social_id=user_info['sub'],
                is_verified=user_info['email_verified'],
                name=user_info.get('name'),
                picture=user_info.get('picture'),
                locale=user_info.get('locale'),
            )

        # Create tokens
        tokens = await token_service.create_tokens(
            user_id=user.id,
            user_agent=request.headers.get("user-agent", ""),
            ip_address=get_client_ip(request),
        )
        if not tokens:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create authentication tokens",
            )

        # Log successful login
        await audit_repo.create({
            "user_id": user.id,
            "action": "login_google",
            "ip_address": get_client_ip(request),
            "user_agent": request.headers.get("user-agent", ""),
            "details": "Logged in with Google",
        })

        return tokens

    except DuplicateError as e:
        logger.error("Google OAuth callback failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except Exception as e:
        logger.error("Google OAuth callback failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authentication failed",
        )


@router.get("/apple/authorize")
async def apple_login(request: Request) -> Response:
    """Start Apple OAuth2 flow."""
    redirect_uri = request.url_for('oauth_callback_apple')
    response = await oauth.apple.authorize_redirect(request, redirect_uri)
    return cast(Response, response)


@router.post("/apple/callback")
async def oauth_callback_apple(
    request: Request,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
    user_info: AppleOAuthUserInfo,
) -> TokenResponse:
    """Handle Apple OAuth2 callback.

    Args:
        request: FastAPI request
        user_repo: User repository
        audit_repo: Audit log repository
        user_info: OAuth user info from Apple

    Returns:
        Token response with access and refresh tokens

    Raises:
        HTTPException: If authentication fails
    """
    try:
        # Try to find existing user
        try:
            user = await user_repo.get_by_email(user_info['email'])

            # Link Apple account if not already linked
            if ProviderType.APPLE.value not in user.social_id:
                user = await user_repo.link_social_account(
                    user_id=user.id,
                    provider=ProviderType.APPLE.value,
                    social_id=user_info['sub'],
                )

        except NotFoundError:
            # Create new user
            user = await user_repo.create_social_user(
                email=user_info['email'],
                provider=ProviderType.APPLE.value,
                social_id=user_info['sub'],
                is_verified=user_info['email_verified'],
                name=user_info.get('name'),
                picture=user_info.get('picture'),
                locale=user_info.get('locale'),
            )

        # Create tokens
        tokens = await token_service.create_tokens(
            user_id=user.id,
            user_agent=request.headers.get("user-agent", ""),
            ip_address=get_client_ip(request),
        )
        if not tokens:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create authentication tokens",
            )

        # Log successful login
        await audit_repo.create({
            "user_id": user.id,
            "action": "login_apple",
            "ip_address": get_client_ip(request),
            "user_agent": request.headers.get("user-agent", ""),
            "details": "Logged in with Apple",
        })

        return tokens

    except DuplicateError as e:
        logger.error("Apple OAuth callback failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except Exception as e:
        logger.error("Apple OAuth callback failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authentication failed",
        )


@router.get("/providers", response_model=list[str])
@requires_admin
async def list_providers() -> list[str]:
    """List available OAuth2 providers."""
    return [provider.value for provider in ProviderType]


@router.get("/stats", response_model=dict[str, int])
@requires_admin
async def get_social_stats(
    user_repo: UserRepo,
) -> dict[str, int]:
    """Get social login statistics for monitoring and analytics.

    Args:
        user_repo: User repository

    Returns:
        Dictionary with provider statistics

    Raises:
        HTTPException: If stats retrieval fails
    """
    try:
        return await user_repo.get_provider_stats()
    except Exception as e:
        logger.error("Failed to get social stats: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get social login statistics",
        )

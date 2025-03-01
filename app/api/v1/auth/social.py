"""Social authentication endpoints following RFC 6749 (OAuth2)."""

import logging
from enum import Enum
from typing import cast

from fastapi import APIRouter, HTTPException, Request, Response, status

from app.core.auth import requires_admin
from app.core.dependencies import AuditRepo, UserRepo
from app.core.errors import AuthError
from app.core.oauth2 import AppleOAuthUserInfo, OAuthUserInfo, oauth
from app.services import AuthService
from app.services.token import TokenResponse

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
    redirect_uri = request.url_for("oauth_callback_google")
    state = request.session.get("oauth_state", "")
    response = await oauth.google.authorize_redirect(request, redirect_uri, state=state)
    return cast(Response, response)


@router.get("/google/callback")
async def oauth_callback_google(
    request: Request,
    response: Response,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
    user_info: OAuthUserInfo,
) -> TokenResponse:
    """Handle Google OAuth2 callback.

    Args:
        request: FastAPI request
        response: FastAPI response
        user_repo: User repository
        audit_repo: Audit log repository
        user_info: OAuth user info from Google

    Returns:
        Token response with access and refresh tokens

    Raises:
        HTTPException: If authentication fails
    """
    try:
        auth_service = AuthService(user_repo, audit_repo)
        return await auth_service.handle_social_auth(
            request=request,
            user_info=user_info,
            provider=ProviderType.GOOGLE.value,
            response=response,
        )
    except AuthError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post("/apple/authorize")
async def apple_login(request: Request) -> Response:
    """Start Apple OAuth2 flow."""
    redirect_uri = request.url_for("oauth_callback_apple")
    state = request.session.get("oauth_state", "")
    response = await oauth.apple.authorize_redirect(request, redirect_uri, state=state)
    return cast(Response, response)


@router.post("/apple/callback")
async def oauth_callback_apple(
    request: Request,
    response: Response,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
    user_info: AppleOAuthUserInfo,
) -> TokenResponse:
    """Handle Apple OAuth2 callback.

    Args:
        request: FastAPI request
        response: FastAPI response
        user_repo: User repository
        audit_repo: Audit log repository
        user_info: OAuth user info from Apple

    Returns:
        Token response with access and refresh tokens

    Raises:
        HTTPException: If authentication fails
    """
    try:
        auth_service = AuthService(user_repo, audit_repo)
        return await auth_service.handle_social_auth(
            request=request,
            user_info=user_info,
            provider=ProviderType.APPLE.value,
            response=response,
        )
    except AuthError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
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
    audit_repo: AuditRepo,
) -> dict[str, int]:
    """Get social login statistics for monitoring and analytics.

    Args:
        user_repo: User repository
        audit_repo: Audit log repository

    Returns:
        Dictionary with provider statistics

    Raises:
        HTTPException: If stats retrieval fails
    """
    try:
        auth_service = AuthService(user_repo, audit_repo)
        return await auth_service.get_provider_stats()
    except AuthError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )

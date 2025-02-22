"""Social authentication endpoints following RFC 6749 (OAuth2).

Supports:
- Google OAuth2 with OpenID Connect
- Apple Sign In with PKCE
"""

import logging
from typing import Literal

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import select

from app.api.v1.auth.dependencies import DBSession
from app.core.config import settings
from app.core.jwt import TokenResponse, token_service
from app.core.oauth2 import (
    AppleOAuth2Config,
    AppleOAuth2Provider,
    GoogleOAuth2Config,
    GoogleOAuth2Provider,
    UserInfo,
)
from app.models import AuditLog, User
from app.schemas import UserResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/social", tags=["social"])

# Initialize OAuth2 providers
google_provider = GoogleOAuth2Provider(
    GoogleOAuth2Config(
        client_id=settings.GOOGLE_CLIENT_ID,
        client_secret=settings.GOOGLE_CLIENT_SECRET.get_secret_value(),
    ),
)

apple_provider = AppleOAuth2Provider(
    AppleOAuth2Config(
        client_id=settings.APPLE_CLIENT_ID,
        client_secret=settings.APPLE_CLIENT_SECRET.get_secret_value(),
        team_id=settings.APPLE_TEAM_ID,
        key_id=settings.APPLE_KEY_ID,
    ),
)

ProviderType = Literal["google", "apple"]


@router.get("/{provider}/authorize")
async def authorize(
    request: Request,
    provider: ProviderType,
) -> dict[str, str]:
    """Get authorization URL for social login.

    Generates PKCE challenge and state parameter for security.
    Stores them in session for verification during callback.

    Args:
        request: FastAPI request object
        provider: OAuth2 provider (google or apple)

    Returns:
        dict: Authorization URL and state parameter

    Raises:
        HTTPException: If provider is invalid or URL generation fails
    """
    try:
        oauth_provider = {
            "google": google_provider,
            "apple": apple_provider,
        }[provider]

        url, state = await oauth_provider.get_authorization_url(request)
        return {
            "url": url,
            "state": state,
        }

    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid provider: {provider}",
        )


@router.get("/{provider}/callback", response_model=UserResponse | TokenResponse)
async def callback(
    request: Request,
    response: Response,
    provider: ProviderType,
    db: DBSession,
) -> UserResponse | TokenResponse:
    """Handle OAuth2 callback and create/link user account.

    For web clients, sets refresh token in HTTP-only cookie
    and returns user data.

    For API clients, returns both access and refresh tokens
    in JSON response.

    Args:
        request: FastAPI request object
        response: FastAPI response object
        provider: OAuth2 provider (google or apple)
        db: Database session

    Returns:
        UserResponse | TokenResponse: User data or tokens

    Raises:
        HTTPException:
            - 400: Invalid provider or OAuth2 error
            - 401: Invalid state parameter
            - 403: Email not verified
    """
    try:
        # Get provider instance
        oauth_provider = {
            "google": google_provider,
            "apple": apple_provider,
        }[provider]

        # Exchange code for token
        token = await oauth_provider.get_access_token(request)

        # Get user info from provider
        user_info: UserInfo = await oauth_provider.get_user_info(dict(token))

        # Check if user exists
        stmt = select(User).where(User.email == user_info["email"])
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()

        if user:
            # Update social ID if not already linked
            if provider not in user.social_id:
                user.social_id[provider] = user_info["sub"]
                await db.commit()
        else:
            # Create new user
            user = User(
                email=user_info["email"],
                password_hash="",  # No password for social auth
                is_verified=user_info["email_verified"],
                social_id={provider: user_info["sub"]},
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)

        # Log social login
        audit_log = AuditLog(
            user_id=user.id,
            action=f"social_login_{provider}",
            ip_address=request.client.host if request.client else "unknown",
            user_agent=request.headers.get("user-agent", ""),
            details=f"Social login via {provider}",
        )
        db.add(audit_log)
        await db.commit()

        # Detect client type from Accept header
        wants_json = "application/json" in request.headers.get("accept", "")

        # Create tokens based on client type
        tokens = await token_service.create_tokens(
            user_id=user.id,
            response=None if wants_json else response,
        )

        # Return tokens for API clients, user data for web clients
        if wants_json and tokens:
            return tokens
        return UserResponse.model_validate(user)

    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid provider: {provider}",
        )
    except Exception as e:
        logger.error("Social login failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

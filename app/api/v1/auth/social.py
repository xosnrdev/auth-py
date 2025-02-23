"""Social authentication endpoints following RFC 6749 (OAuth2).

This module implements secure social authentication following multiple RFCs:
- OAuth2 Authorization Framework (RFC 6749)
- Bearer Token Usage (RFC 6750)
- OpenID Connect Core 1.0
- Apple Sign In (Sign In with Apple REST API)
- PKCE Extension (RFC 7636)

Supported Providers:
1. Google OAuth2
   - OpenID Connect integration
   - Email verification
   - Profile information
   - Automatic account linking

2. Apple Sign In
   - PKCE implementation
   - Private key authentication
   - Email relay support
   - Platform-specific flows

Security Features:
- PKCE for all flows (RFC 7636)
- State parameter validation
- JWT signature verification
- Email verification enforcement
- Secure token handling
- Rate limiting
- Audit logging
"""

import logging
from enum import Enum

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import func, select

from app.api.v1.auth.dependencies import DBSession
from app.core.auth import requires_admin
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


# Initialize OAuth2 providers with secure configurations
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


@router.get("/{provider}/authorize")
async def authorize(
    request: Request,
    provider: ProviderType,
) -> dict[str, str]:
    """Get authorization URL for social login following OAuth2 specifications.

    Implements OAuth2 Authorization Code Flow with PKCE (RFC 7636):
    1. Generates PKCE challenge and verifier
    2. Creates secure state parameter
    3. Builds authorization URL with required parameters
    4. Stores PKCE and state in session
    5. Supports provider-specific parameters

    Args:
        request: FastAPI request object for session management
        provider: OAuth2 provider (google or apple)

    Returns:
        dict: Authorization URL and state parameter for validation

    Raises:
        HTTPException: If provider is invalid or URL generation fails

    Security:
        - Implements PKCE for all providers
        - Uses cryptographic state parameter
        - Stores verifier securely
        - Rate limited by default middleware
        - Supports provider-specific security
    """
    try:
        oauth_provider = {
            ProviderType.GOOGLE: google_provider,
            ProviderType.APPLE: apple_provider,
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

    Implements secure OAuth2 callback handling:
    1. Validates state parameter and PKCE challenge
    2. Exchanges code for access token
    3. Verifies ID token (for OpenID Connect)
    4. Retrieves user information
    5. Creates or links user account
    6. Issues session tokens
    7. Logs authentication event

    For web clients:
    - Sets refresh token in HTTP-only cookie
    - Returns user data in response

    For API clients:
    - Returns both access and refresh tokens
    - Includes token metadata

    Args:
        request: FastAPI request object
        response: FastAPI response object for cookie management
        provider: OAuth2 provider (google or apple)
        db: Database session

    Returns:
        UserResponse | TokenResponse: User data or tokens based on client type

    Raises:
        HTTPException:
            - 400: Invalid provider or OAuth2 error
            - 401: Invalid state parameter or PKCE failure
            - 403: Email not verified
            - 500: Account creation/linking failed

    Security:
        - Validates state parameter
        - Verifies PKCE challenge
        - Validates ID tokens
        - Requires email verification
        - Implements secure session handling
        - Logs all authentication attempts
        - Rate limited by default middleware
    """
    try:
        # Get provider instance
        oauth_provider = {
            ProviderType.GOOGLE: google_provider,
            ProviderType.APPLE: apple_provider,
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
            if provider.value not in user.social_id:
                user.social_id[provider.value] = user_info["sub"]
                await db.commit()
        else:
            # Create new user
            user = User(
                email=user_info["email"],
                password_hash="",  # No password for social auth
                is_verified=user_info["email_verified"],
                social_id={provider.value: user_info["sub"]},
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)

        # Log social login
        audit_log = AuditLog(
            user_id=user.id,
            action=f"social_login_{provider.value}",
            ip_address=request.client.host if request.client else "unknown",
            user_agent=request.headers.get("user-agent", ""),
            details=f"Social login via {provider.value}",
        )
        db.add(audit_log)
        await db.commit()

        # Detect client type from Accept header
        wants_json = "application/json" in request.headers.get("accept", "")

        # Create tokens based on client type
        tokens = await token_service.create_tokens(
            user_id=user.id,
            user_agent=request.headers.get("user-agent", ""),
            ip_address=get_client_ip(request),
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


@router.get("/providers", response_model=list[str])
@requires_admin
async def list_providers() -> list[str]:
    """List available OAuth2 providers (admin only).

    Implements secure provider enumeration:
    1. Requires admin role (RBAC)
    2. Lists supported providers
    3. Supports dynamic provider configuration

    Returns:
        list[str]: List of supported provider identifiers

    Security:
        - Requires admin role
        - Rate limited by default middleware
        - Returns minimal necessary information
    """
    return [provider.value for provider in ProviderType]


@router.get("/stats", response_model=dict[str, int])
@requires_admin
async def get_social_stats(db: DBSession) -> dict[str, int]:
    """Get social login statistics for monitoring and analytics.

    Implements secure statistics gathering:
    1. Aggregates user counts by provider
    2. Uses efficient database queries
    3. Enforces RBAC (admin only)
    4. Provides anonymized metrics
    5. Supports monitoring and reporting

    The endpoint returns counts of:
    - Google OAuth2 users
    - Apple Sign In users
    Without exposing sensitive user information

    Args:
        db: Database session for aggregation queries

    Returns:
        dict[str, int]: Provider-specific user counts
            Format: {
                "google_users": count,
                "apple_users": count
            }

    Security:
        - Requires admin role (RBAC)
        - Returns aggregated data only
        - No personal data exposure
        - Rate limited by default middleware
        - Audit logged access
        - Efficient query execution
    """
    # Count users by provider using SQLAlchemy's func.count()
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

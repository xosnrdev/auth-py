"""OAuth2 integration using Authlib."""

import logging
from typing import Annotated, TypedDict

from authlib.integrations.starlette_client import OAuth
from fastapi import Depends, HTTPException, Request, status

from app.core.config import settings

logger = logging.getLogger(__name__)

class CustomOAuth(OAuth):
    """Custom OAuth class with state validation."""

    async def validate_state(self, request: Request) -> bool:
        """Validate state parameter."""
        state = request.query_params.get('state')
        session_state = request.session.get('oauth_state')
        logger.debug("Validating state - Request: %s, Session: %s", state, session_state)
        return state == session_state

class UserInfo(TypedDict):
    """Common user info structure following OpenID Connect."""
    provider: str
    sub: str
    email: str
    email_verified: bool
    name: str | None
    picture: str | None
    locale: str | None

oauth: OAuth = CustomOAuth()  # type: ignore[no-untyped-call]

# Register providers only if credentials are configured
if settings.GOOGLE_CLIENT_ID and settings.GOOGLE_CLIENT_SECRET:
    oauth.register(
        name='google',
        client_id=settings.GOOGLE_CLIENT_ID,
        client_secret=settings.GOOGLE_CLIENT_SECRET.get_secret_value(),
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={
            'scope': 'openid email profile',
            'code_challenge_method': 'S256',
            'response_type': 'code',
            'response_mode': 'query',
            'prompt': 'select_account'
        }
    )
    logger.info("Google OAuth provider registered")
else:
    logger.warning("Google OAuth provider not configured - missing credentials")

if (settings.APPLE_CLIENT_ID and settings.APPLE_CLIENT_SECRET and
    settings.APPLE_TEAM_ID and settings.APPLE_KEY_ID):
    oauth.register(
        name='apple',
        client_id=settings.APPLE_CLIENT_ID,
        client_secret=settings.APPLE_CLIENT_SECRET.get_secret_value(),
        authorize_url='https://appleid.apple.com/auth/authorize',
        token_url='https://appleid.apple.com/auth/token',
        client_kwargs={
            'scope': 'openid email name',
            'code_challenge_method': 'S256',
            'response_mode': 'form_post'
        }
    )
    logger.info("Apple OAuth provider registered")
else:
    logger.warning("Apple OAuth provider not configured - missing credentials")

def is_provider_configured(provider: str) -> bool:
    """Check if an OAuth provider is configured and available."""
    client = getattr(oauth, provider, None)
    return client is not None

async def require_user_info(
    request: Request,
    provider: str = 'google'
) -> UserInfo:
    """Get validated user info from OAuth provider."""
    try:
        if not is_provider_configured(provider):
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail=f"OAuth provider '{provider}' is not configured"
            )

        client = getattr(oauth, provider)
        logger.debug(
            "OAuth callback received - URL: %s, Query Params: %s, Session: %s",
            str(request.url),
            request.query_params,
            request.session
        )

        # Token exchange
        token = await client.authorize_access_token(request)
        if not isinstance(token, dict):
            raise ValueError("Invalid token response format")

        logger.debug("OAuth token response: %s", {
            k: "..." if k in ("id_token", "access_token") else v
            for k, v in token.items()
        })

        # Get user info
        user = await client.userinfo(token=token)
        if not user:
            raise ValueError("Failed to get user info")

        logger.debug("User info: %s", {
            k: v for k, v in user.items() if k not in ('sub',)
        })

        if not user.get('email'):
            raise ValueError("Email missing from user info")

        if not user.get('email_verified', False):
            raise ValueError("Email must be verified")

        if not user.get('sub'):
            raise ValueError("Subject identifier missing from user info")

        return UserInfo(
            provider=provider,
            sub=str(user['sub']),
            email=str(user['email']).lower(),
            email_verified=bool(user['email_verified']),
            name=user.get('name'),
            picture=user.get('picture'),
            locale=user.get('locale')
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed: {str(e)}"
        )

OAuthUserInfo = Annotated[UserInfo, Depends(require_user_info)]

async def require_apple_user_info(request: Request) -> UserInfo:
    """Get validated user info from Apple OAuth provider."""
    return await require_user_info(request, provider='apple')

AppleOAuthUserInfo = Annotated[UserInfo, Depends(require_apple_user_info)]

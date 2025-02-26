"""OAuth2 integration using Authlib."""

from typing import Annotated, TypedDict

from authlib.integrations.starlette_client import OAuth
from fastapi import Depends, HTTPException, Request, status

from app.core.config import settings

oauth: OAuth = OAuth()  # type: ignore[no-untyped-call]

class UserInfo(TypedDict):
    """Common user info structure following OpenID Connect."""
    provider: str
    sub: str
    email: str
    email_verified: bool
    name: str | None
    picture: str | None
    locale: str | None

oauth.register(
    name='google',
    client_id=settings.GOOGLE_CLIENT_ID,
    client_secret=settings.GOOGLE_CLIENT_SECRET.get_secret_value(),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
        'code_challenge_method': 'S256'
    }
)

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

async def require_user_info(
    request: Request,
    provider: str = 'google'
) -> UserInfo:
    """Get validated user info from OAuth provider."""
    try:
        client = getattr(oauth, provider, None)
        if not client:
            raise ValueError(f"Unknown provider: {provider}")

        token = await client.authorize_access_token(request)
        user = await client.parse_id_token(request, token)

        if not user.get('email_verified', False):
            raise ValueError("Email must be verified")

        return UserInfo(
            provider=provider,
            sub=str(user['sub']),
            email=str(user['email']).lower(),
            email_verified=bool(user['email_verified']),
            name=user.get('name'),
            picture=user.get('picture'),
            locale=user.get('locale')
        )

    except (ValueError, KeyError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )

OAuthUserInfo = Annotated[UserInfo, Depends(require_user_info)]

async def require_apple_user_info(request: Request) -> UserInfo:
    """Get validated user info from Apple OAuth provider."""
    return await require_user_info(request, provider='apple')

AppleOAuthUserInfo = Annotated[UserInfo, Depends(require_apple_user_info)]

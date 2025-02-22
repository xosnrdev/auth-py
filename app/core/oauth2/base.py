"""Base OAuth2 provider implementation following RFC 6749."""

import secrets
from abc import ABC, abstractmethod
from typing import Any, TypedDict

from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import HTTPException, Request, status
from pydantic import BaseModel, ConfigDict


class OAuth2Config(BaseModel):
    """OAuth2 provider configuration."""

    model_config = ConfigDict(
        frozen=True,  # Immutable configuration
    )

    name: str
    client_id: str
    client_secret: str
    authorize_url: str
    token_url: str
    userinfo_url: str
    scope: list[str]


class TokenResponse(TypedDict):
    """OAuth2 token response."""

    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str | None
    id_token: str | None


class OAuth2Provider(ABC):
    """Base OAuth2 provider with PKCE support."""

    def __init__(self, config: OAuth2Config) -> None:
        """Initialize OAuth2 provider.

        Args:
            config: Provider configuration
        """
        self.config = config
        self.oauth = OAuth()  # type: ignore[no-untyped-call] # Authlib's OAuth class is untyped
        self.client = self.oauth.register(
            name=config.name,
            client_id=config.client_id,
            client_secret=config.client_secret,
            authorize_url=config.authorize_url,
            authorize_params=None,
            token_url=config.token_url,
            token_endpoint_auth_method="client_secret_post",
            userinfo_url=config.userinfo_url,
            client_kwargs={
                "scope": " ".join(config.scope),
                "code_challenge_method": "S256",  # Enable PKCE
            },
        )

    async def get_authorization_url(self, request: Request) -> tuple[str, str]:
        """Get authorization URL with PKCE.

        Args:
            request: FastAPI request object

        Returns:
            tuple[str, str]: Authorization URL and state parameter

        Raises:
            HTTPException: If authorization URL generation fails
        """
        try:
            # Generate PKCE challenge
            code_verifier = secrets.token_urlsafe(64)
            request.session["code_verifier"] = code_verifier

            # Generate state parameter
            state = secrets.token_urlsafe(32)
            request.session["oauth_state"] = state

            url = await self.client.authorize_redirect(
                request,
                state=state,
                code_verifier=code_verifier,
            )
            return str(url), state
        except OAuthError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to generate authorization URL: {str(e)}",
            ) from e

    async def get_access_token(self, request: Request) -> TokenResponse:
        """Get access token using authorization code.

        Args:
            request: FastAPI request object

        Returns:
            TokenResponse: Access token response

        Raises:
            HTTPException: If token retrieval fails
        """
        try:
            # Verify state parameter
            state = request.query_params.get("state")
            stored_state = request.session.pop("oauth_state", None)
            if not state or not stored_state or state != stored_state:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid state parameter",
                )

            # Get code verifier from session
            code_verifier = request.session.pop("code_verifier", None)
            if not code_verifier:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Missing PKCE code verifier",
                )

            # Exchange code for token
            token: TokenResponse = await self.client.authorize_access_token(
                request,
                code_verifier=code_verifier,
            )
            return token
        except OAuthError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to get access token: {str(e)}",
            ) from e

    @abstractmethod
    async def get_user_info(self, token: dict[str, Any]) -> dict[str, Any]:
        """Get user info from provider.

        Args:
            token: Access token response

        Returns:
            dict[str, Any]: User info from provider

        Raises:
            HTTPException: If user info retrieval fails
        """
        raise NotImplementedError

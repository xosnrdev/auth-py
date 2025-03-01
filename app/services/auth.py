"""Authentication service for managing user authentication flows."""

import logging
from datetime import UTC, datetime, timedelta
from secrets import token_hex
from typing import cast
from uuid import UUID

from fastapi import Request, Response
from fastapi.security import OAuth2PasswordRequestForm

from app.core.config import settings
from app.core.errors import AuthError, DuplicateError, NotFoundError
from app.core.oauth2 import AppleOAuthUserInfo, OAuthUserInfo
from app.core.security import get_password_hash, verify_password
from app.models import User
from app.repositories import AuditLogRepository, UserRepository
from app.services.email import email_service
from app.services.token import TokenResponse, TokenType, token_service
from app.utils.request import get_client_ip

logger = logging.getLogger(__name__)

MAX_LOGIN_ATTEMPTS = 5
LOGIN_ATTEMPT_WINDOW_SECS = 3600


class AuthService:
    """Authentication service for managing user authentication flows.

    This service handles:
    - User login with email/password
    - Social authentication (Google, Apple)
    - Token refresh
    - User logout and token revocation
    - Session management
    """

    def __init__(
        self,
        user_repo: UserRepository,
        audit_repo: AuditLogRepository,
    ) -> None:
        """Initialize auth service.

        Args:
            user_repo: User repository for user operations
            audit_repo: Audit repository for logging auth events
        """
        self._user_repo = user_repo
        self._audit_repo = audit_repo

    async def login(
        self,
        request: Request,
        form_data: OAuth2PasswordRequestForm,
        response: Response | None = None,
    ) -> TokenResponse:
        """Authenticate user with email/password.

        Args:
            request: FastAPI request
            form_data: OAuth2 password form data
            response: Optional FastAPI response for setting cookies

        Returns:
            Token response with access and refresh tokens

        Raises:
            AuthError: If authentication fails
            RateLimitError: If too many failed attempts
        """
        try:
            # Get user by email
            user = await self._user_repo.get_by_email(form_data.username.lower())

            # Verify password
            if not verify_password(form_data.password, user.password_hash):
                await self._handle_failed_login(request, user)
                raise AuthError("Invalid credentials")

            # Check user status
            if not user.is_active:
                raise AuthError("Account is disabled")
            if not user.is_verified:
                raise AuthError("Email not verified")

            # Create tokens
            tokens = await token_service.create_tokens(
                user_id=user.id,
                user_agent=request.headers.get("user-agent", ""),
                ip_address=get_client_ip(request),
                response=response,
            )

            # Log successful login
            await self._audit_repo.create(
                {
                    "user_id": user.id,
                    "action": "login",
                    "ip_address": get_client_ip(request),
                    "user_agent": request.headers.get("user-agent", ""),
                    "details": "Successful login",
                }
            )

            return TokenResponse(
                access_token=cast(dict[str, str], tokens)["access_token"],
                refresh_token=cast(dict[str, str], tokens)["refresh_token"],
                token_type="bearer",
                expires_in=settings.JWT_ACCESS_TOKEN_TTL_SECS,
            )

        except NotFoundError:
            raise AuthError("Invalid credentials")

        except Exception as e:
            logger.error("Login failed: %s", str(e))
            raise AuthError("Authentication failed")

    async def refresh_token(
        self,
        request: Request,
        refresh_token: str,
        response: Response | None = None,
    ) -> TokenResponse:
        """Refresh access token using refresh token.

        Args:
            request: FastAPI request
            refresh_token: Refresh token
            response: Optional FastAPI response for setting cookies

        Returns:
            Token response with new access and refresh tokens

        Raises:
            AuthError: If token refresh fails
        """
        try:
            # Verify refresh token
            token_data = await token_service.verify_token(
                refresh_token, TokenType.REFRESH
            )

            try:
                # Get user by ID
                user = await self._user_repo.get_by_id(UUID(token_data.sub))
                if not user.is_active:
                    await token_service.revoke_token(refresh_token)
                    raise AuthError("User not found or inactive")

                # Create new tokens
                is_api_client = "application/json" in request.headers.get(
                    "content-type", ""
                )
                tokens = await token_service.create_tokens(
                    user_id=user.id,
                    user_agent=request.headers.get("user-agent", ""),
                    ip_address=get_client_ip(request),
                    response=None if is_api_client else response,
                )

                # Revoke old token
                await token_service.revoke_token(refresh_token)

                # Log token refresh
                await self._audit_repo.create(
                    {
                        "user_id": user.id,
                        "action": "refresh_token",
                        "ip_address": get_client_ip(request),
                        "user_agent": request.headers.get("user-agent", ""),
                        "details": "Refreshed access token",
                    }
                )

                if is_api_client:
                    return TokenResponse(
                        access_token=cast(dict[str, str], tokens)["access_token"],
                        refresh_token=cast(dict[str, str], tokens)["refresh_token"],
                        token_type="bearer",
                        expires_in=settings.JWT_ACCESS_TOKEN_TTL_SECS,
                    )
                else:
                    return TokenResponse(
                        access_token=cast(dict[str, str], tokens)["access_token"],
                        refresh_token=None,
                        token_type="bearer",
                        expires_in=settings.JWT_ACCESS_TOKEN_TTL_SECS,
                    )

            except NotFoundError:
                await token_service.revoke_token(refresh_token)
                raise AuthError("User not found or inactive")

        except Exception as e:
            logger.error("Token refresh failed: %s", str(e))
            raise AuthError(str(e))

    async def logout(
        self,
        request: Request,
        response: Response,
        user: User,
        access_token: str,
    ) -> None:
        """Logout user and revoke current session.

        Args:
            request: FastAPI request
            response: FastAPI response
            user: Current authenticated user
            access_token: Current access token

        Raises:
            AuthError: If logout fails
        """
        try:
            # Revoke current access token
            await token_service.revoke_token(access_token)

            # Revoke all user tokens
            await token_service.revoke_all_user_tokens(user.id.hex)

            # Log logout
            await self._audit_repo.create(
                {
                    "user_id": user.id,
                    "action": "logout",
                    "ip_address": get_client_ip(request),
                    "user_agent": request.headers.get("user-agent", ""),
                    "details": "Logged out",
                }
            )

            # Clear refresh token cookie
            response.delete_cookie(key="refresh_token")

        except Exception as e:
            logger.error("Logout failed: %s", str(e))
            raise AuthError(str(e))

    async def _handle_failed_login(
        self,
        request: Request,
        user: User,
    ) -> None:
        """Handle failed login attempt.

        Args:
            request: FastAPI request
            user: User that failed to login

        Raises:
            RateLimitError: If too many failed attempts
        """
        # Log failed attempt
        await self._audit_repo.create(
            {
                "user_id": user.id,
                "action": "login_failed",
                "ip_address": get_client_ip(request),
                "user_agent": request.headers.get("user-agent", ""),
                "details": "Failed login attempt",
            }
        )

        # Check failed attempts in time window
        since = datetime.now(UTC).timestamp() - LOGIN_ATTEMPT_WINDOW_SECS
        failed_attempts = await self._audit_repo.count(
            {
                "user_id": user.id,
                "action": "login_failed",
                "created_at_gt": since,
            }
        )

        if failed_attempts >= MAX_LOGIN_ATTEMPTS:
            # Disable account if too many failed attempts
            await self._user_repo.update(user.id, {"is_active": False})
            logger.warning(
                "Account disabled due to too many failed attempts: %s",
                user.email,
            )
            raise AuthError("Too many failed attempts. Account disabled.")

    async def handle_social_auth(
        self,
        request: Request,
        user_info: OAuthUserInfo | AppleOAuthUserInfo,
        provider: str,
        response: Response | None = None,
    ) -> TokenResponse:
        """Handle social authentication flow.

        Args:
            request: FastAPI request
            user_info: OAuth user info from provider
            provider: OAuth provider (google, apple)
            response: Optional FastAPI response for setting cookies

        Returns:
            Token response with access and refresh tokens

        Raises:
            AuthError: If authentication fails
            DuplicateError: If account linking fails
        """
        try:
            # Try to find existing user
            try:
                user = await self._user_repo.get_by_email(user_info["email"])

                # Link social account if not already linked
                if provider not in user.social_id:
                    user = await self._user_repo.link_social_account(
                        user_id=user.id,
                        provider=provider,
                        social_id=user_info["sub"],
                    )

            except NotFoundError:
                # Create new user
                user = await self._user_repo.create_social_user(
                    email=user_info["email"],
                    provider=provider,
                    social_id=user_info["sub"],
                    is_verified=user_info.get("email_verified", False),
                    name=user_info.get("name"),
                    picture=user_info.get("picture"),
                    locale=user_info.get("locale"),
                )

            # Create tokens
            tokens = await token_service.create_tokens(
                user_id=user.id,
                user_agent=request.headers.get("user-agent", ""),
                ip_address=get_client_ip(request),
                response=response,
            )

            # Log successful login
            await self._audit_repo.create(
                {
                    "user_id": user.id,
                    "action": f"login_{provider}",
                    "ip_address": get_client_ip(request),
                    "user_agent": request.headers.get("user-agent", ""),
                    "details": f"Logged in with {provider}",
                }
            )

            return TokenResponse(
                access_token=cast(dict[str, str], tokens)["access_token"],
                refresh_token=cast(dict[str, str], tokens)["refresh_token"],
                token_type="bearer",
                expires_in=settings.JWT_ACCESS_TOKEN_TTL_SECS,
            )

        except DuplicateError as e:
            logger.error("Social auth failed: %s", str(e))
            raise AuthError(str(e))

        except Exception as e:
            logger.error("Social auth failed: %s", str(e))
            raise AuthError("Authentication failed")

    async def get_provider_stats(self) -> dict[str, int]:
        """Get social login statistics.

        Returns:
            Dictionary with provider statistics

        Raises:
            AuthError: If stats retrieval fails
        """
        try:
            return await self._user_repo.get_provider_stats()
        except Exception as e:
            logger.error("Failed to get social stats: %s", str(e))
            raise AuthError("Failed to get social login statistics")

    async def request_password_reset(
        self,
        request: Request,
        email: str,
    ) -> None:
        """Request password reset for user.

        Args:
            request: FastAPI request
            email: User email

        Raises:
            AuthError: If request fails
        """
        try:
            # Get user by email
            user = await self._user_repo.get_by_email(email.lower())

            # Generate reset token
            reset_token = token_hex(32)
            reset_token_expires = datetime.now(UTC) + timedelta(
                seconds=settings.VERIFICATION_CODE_TTL_SECS,
            )

            # Update user with reset token
            await self._user_repo.update(
                user.id,
                {
                    "reset_token": reset_token,
                    "reset_token_expires_at": reset_token_expires,
                },
            )

            # Send reset email
            reset_url = f"{settings.FRONTEND_URL.unicode_string()}{settings.PASSWORD_RESET_URI}?token={reset_token}"
            await email_service.send_password_reset_email(user.email, reset_url)

            # Log password reset request
            await self._audit_repo.create(
                {
                    "user_id": user.id,
                    "action": "password_reset_request",
                    "ip_address": get_client_ip(request),
                    "user_agent": request.headers.get("user-agent", ""),
                    "details": "Password reset requested",
                }
            )

        except NotFoundError:
            # Return silently to prevent email enumeration
            pass

        except Exception as e:
            logger.error("Password reset request failed: %s", str(e))
            raise AuthError("Failed to process password reset request")

    async def verify_password_reset(
        self,
        request: Request,
        token: str,
        new_password: str,
    ) -> None:
        """Verify password reset token and set new password.

        Args:
            request: FastAPI request
            token: Reset token
            new_password: New password

        Raises:
            AuthError: If verification fails
        """
        try:
            # Get user by reset token
            user = await self._user_repo.get_by_reset_token(token)

            # Update password
            password_hash = get_password_hash(new_password)
            await self._user_repo.update(
                user.id,
                {
                    "password_hash": password_hash,
                    "reset_token": None,
                    "reset_token_expires_at": None,
                },
            )

            # Log password reset
            await self._audit_repo.create(
                {
                    "user_id": user.id,
                    "action": "password_reset",
                    "ip_address": get_client_ip(request),
                    "user_agent": request.headers.get("user-agent", ""),
                    "details": "Password reset successful",
                }
            )

            # Revoke all existing sessions
            await token_service.revoke_all_user_tokens(user.id.hex)

        except NotFoundError:
            raise AuthError("Invalid or expired reset token")

        except Exception as e:
            logger.error("Password reset verification failed: %s", str(e))
            raise AuthError("Failed to reset password")

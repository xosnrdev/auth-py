"""Authentication service for managing user authentication flows."""

import logging
from datetime import UTC, datetime, timedelta
from secrets import token_hex
from typing import cast
from uuid import UUID

from fastapi import Request, Response
from fastapi.security import OAuth2PasswordRequestForm

from app.core.config import settings
from app.core.errors import AuthError, DuplicateError, NotFoundError, RateLimitError
from app.core.oauth2 import AppleOAuthUserInfo, OAuthUserInfo
from app.core.security import get_password_hash, verify_password
from app.models.user import User, UserRole
from app.repositories.audit import AuditLogRepository
from app.repositories.token import TokenRepository
from app.repositories.user import UserRepository
from app.schemas.audit import AuditLogCreate
from app.schemas.token import TokenResponse, TokenType
from app.schemas.user import PasswordResetVerify
from app.services.audit import AuditService
from app.services.email import email_service
from app.services.token import TokenService
from app.utils.request import get_client_ip

logger = logging.getLogger(__name__)


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
        token_repo: TokenRepository,
    ) -> None:
        """Initialize auth service.

        Args:
            user_repo: User repository for user operations
            audit_repo: Audit repository for logging auth events
            token_repo: Token repository for token operations
        """
        self._user_repo = user_repo
        self._audit_repo = audit_repo
        self._token_service = TokenService(token_repo)

    async def _check_rate_limit(
        self,
        request: Request,
        action: str,
        max_attempts: int,
        error_message: str | None = None,
    ) -> None:
        """Check if IP address has exceeded rate limit for a specific action.

        Args:
            request: FastAPI request
            action: The action to check rate limit for (e.g. 'login_failed', 'refresh_token_failed')
            max_attempts: Maximum number of attempts allowed
            error_message: Optional custom error message. If not provided, a default one is used.

        Raises:
            RateLimitError: If too many failed attempts from IP
        """
        ip_address = get_client_ip(request)

        # Get recent failed attempts from this IP
        audit_service = AuditService(self._audit_repo)
        failed_attempts = await self._audit_repo.get_by_ip_address(
            ip_address=ip_address,
            action=action,
            since=datetime.now(UTC)
            - timedelta(seconds=settings.RATE_LIMIT_WINDOW_SECS),
        )

        # Check if IP has exceeded limit
        if len(failed_attempts) >= max_attempts:
            # Log IP blocked
            await audit_service.create_log(
                AuditLogCreate(
                    user_id=None,
                    action="ip_blocked",
                    ip_address=ip_address,
                    user_agent=request.headers.get("user-agent", ""),
                    details=f"IP address blocked due to {max_attempts} failed {action.replace('_', ' ')}s",
                )
            )
            if error_message is None:
                error_message = f"Too many failed attempts. Try again in {settings.RATE_LIMIT_WINDOW_SECS // 60} minutes."
            raise RateLimitError(error_message)

    async def _check_ip_rate_limit(self, request: Request) -> None:
        """Check if IP address has exceeded failed login attempts.

        Args:
            request: FastAPI request

        Raises:
            RateLimitError: If too many failed attempts from IP
        """
        await self._check_rate_limit(
            request=request,
            action="login_failed",
            max_attempts=settings.MAX_LOGIN_ATTEMPTS,
            error_message=f"Too many failed login attempts from this IP. Try again in {settings.RATE_LIMIT_WINDOW_SECS // 60} minutes.",
        )

    async def _check_refresh_token_rate_limit(self, request: Request) -> None:
        """Check if IP address has exceeded refresh token attempts.

        Args:
            request: FastAPI request

        Raises:
            RateLimitError: If too many failed attempts from IP
        """
        await self._check_rate_limit(
            request=request,
            action="refresh_token_failed",
            max_attempts=settings.RATE_LIMIT_REQUESTS,
        )

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
            # Get user by email first
            try:
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

                # Check IP rate limit only after user-specific checks
                await self._check_ip_rate_limit(request)

                # Reset failed login attempts on successful login
                await self._user_repo.reset_failed_login(user.id)

                # Create tokens
                tokens = await self._token_service.create_tokens(
                    user_id=user.id,
                    user_agent=request.headers.get("user-agent", ""),
                    ip_address=get_client_ip(request),
                    response=response,
                )

                # Log successful login
                audit_service = AuditService(self._audit_repo)
                await audit_service.create_log(
                    AuditLogCreate(
                        user_id=user.id,
                        action="login",
                        ip_address=get_client_ip(request),
                        user_agent=request.headers.get("user-agent", ""),
                        details="Successful login",
                    )
                )

                # For web clients
                if tokens is None:
                    return TokenResponse(
                        access_token=request.session["access_token"],
                        refresh_token=None,
                        token_type="bearer",
                        expires_in=settings.JWT_ACCESS_TOKEN_TTL_SECS,
                    )

                # For API clients
                return tokens

            except NotFoundError:
                # Check IP rate limit for non-existent users
                await self._check_ip_rate_limit(request)

                # Get recent failed attempts from this IP for non-existent users
                audit_service = AuditService(self._audit_repo)
                failed_attempts = await self._audit_repo.get_by_ip_address(
                    ip_address=get_client_ip(request),
                    action="login_failed",
                    since=datetime.now(UTC)
                    - timedelta(seconds=settings.RATE_LIMIT_WINDOW_SECS),
                )

                # Log failed login attempt for non-existent user
                await audit_service.create_log(
                    AuditLogCreate(
                        user_id=None,  # No user ID since user doesn't exist
                        action="login_failed",
                        ip_address=get_client_ip(request),
                        user_agent=request.headers.get("user-agent", ""),
                        details=f"Failed login attempt for non-existent user: {form_data.username}",
                    )
                )

                # Apply rate limiting for non-existent users
                if (
                    len(failed_attempts) >= settings.MAX_LOGIN_ATTEMPTS - 1
                ):  # -1 to count current attempt
                    raise RateLimitError(
                        f"Too many failed login attempts. Try again in {settings.RATE_LIMIT_WINDOW_SECS // 60} minutes."
                    )

                raise AuthError("Invalid credentials")

        except RateLimitError:
            raise

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
            RateLimitError: If too many failed attempts
        """
        try:
            # Check rate limit before processing
            await self._check_refresh_token_rate_limit(request)

            # Verify refresh token
            token_data = await self._token_service.verify_token(
                refresh_token, TokenType.REFRESH
            )

            try:
                # Get user by ID
                user = await self._user_repo.get_by_id(UUID(token_data.sub))
                if not user.is_active:
                    await self._token_service.revoke_token(refresh_token)
                    raise AuthError("User not found or inactive")

                # Create new tokens
                is_api_client = "application/json" in request.headers.get(
                    "content-type", ""
                )
                tokens = await self._token_service.create_tokens(
                    user_id=user.id,
                    user_agent=request.headers.get("user-agent", ""),
                    ip_address=get_client_ip(request),
                    request=request,
                    response=None if is_api_client else response,
                )

                # Log successful token refresh
                audit_service = AuditService(self._audit_repo)
                await audit_service.create_log(
                    AuditLogCreate(
                        user_id=user.id,
                        action="refresh_token",
                        ip_address=get_client_ip(request),
                        user_agent=request.headers.get("user-agent", ""),
                        details="Refreshed access token",
                    )
                )

                # For web clients
                if tokens is None:
                    result = TokenResponse(
                        access_token=cast(str, request.session.get("access_token")),
                        refresh_token=None,
                        token_type="bearer",
                        expires_in=settings.JWT_ACCESS_TOKEN_TTL_SECS,
                    )
                else:
                    # For API clients
                    result = tokens

                # Revoke old token after creating the response
                await self._token_service.revoke_token(refresh_token)

                return result

            except NotFoundError:
                # Log failed refresh attempt
                audit_service = AuditService(self._audit_repo)
                await audit_service.create_log(
                    AuditLogCreate(
                        user_id=None,
                        action="refresh_token_failed",
                        ip_address=get_client_ip(request),
                        user_agent=request.headers.get("user-agent", ""),
                        details="Failed refresh token attempt - User not found",
                    )
                )
                await self._token_service.revoke_token(refresh_token)
                raise AuthError("User not found or inactive")

        except RateLimitError:
            raise

        except Exception as e:
            # Log failed refresh attempt
            audit_service = AuditService(self._audit_repo)
            await audit_service.create_log(
                AuditLogCreate(
                    user_id=None,
                    action="refresh_token_failed",
                    ip_address=get_client_ip(request),
                    user_agent=request.headers.get("user-agent", ""),
                    details=f"Failed refresh token attempt - {str(e)}",
                )
            )
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
            await self._token_service.revoke_token(access_token)

            # Revoke all user tokens
            await self._token_service.revoke_all_user_tokens(user.id.hex)

            # Log logout
            audit_service = AuditService(self._audit_repo)
            await audit_service.create_log(
                AuditLogCreate(
                    user_id=user.id,
                    action="logout",
                    ip_address=get_client_ip(request),
                    user_agent=request.headers.get("user-agent", ""),
                    details="Logged out",
                )
            )

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
            user: User instance

        Raises:
            RateLimitError: If too many failed attempts
        """
        # Increment failed login attempts
        updated_user = await self._user_repo.increment_failed_login(user.id)

        # Log failed login attempt
        audit_service = AuditService(self._audit_repo)
        await audit_service.create_log(
            AuditLogCreate(
                user_id=user.id,
                action="login_failed",
                ip_address=get_client_ip(request),
                user_agent=request.headers.get("user-agent", ""),
                details=f"Failed login attempt ({updated_user.failed_login_attempts}/{settings.MAX_LOGIN_ATTEMPTS})",
            )
        )

        # First check if account should be disabled
        if updated_user.failed_login_attempts >= settings.MAX_LOGIN_ATTEMPTS - 1:
            # Disable account
            await self._user_repo.disable_account(user.id)

            # Log account disabled
            await audit_service.create_log(
                AuditLogCreate(
                    user_id=user.id,
                    action="account_disabled",
                    ip_address=get_client_ip(request),
                    user_agent=request.headers.get("user-agent", ""),
                    details=f"Account disabled due to {settings.MAX_LOGIN_ATTEMPTS} failed login attempts",
                )
            )

            raise RateLimitError(
                f"Account disabled due to {settings.MAX_LOGIN_ATTEMPTS} failed login attempts"
            )

        # Then check rate limit window only if account is not disabled
        if (
            updated_user.last_failed_login_at
            and (datetime.now(UTC) - updated_user.last_failed_login_at).total_seconds()
            < settings.RATE_LIMIT_WINDOW_SECS
        ):
            remaining_attempts = (
                settings.MAX_LOGIN_ATTEMPTS - updated_user.failed_login_attempts
            )
            raise RateLimitError(
                f"Too many failed login attempts. {remaining_attempts} attempts remaining."
            )

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
            # Try to find existing user by OAuth ID first
            try:
                user = await self._user_repo.get_by_oauth_id(
                    provider=provider,
                    oauth_id=user_info["sub"],
                )
            except NotFoundError:
                # Try to find by email
                try:
                    user = await self._user_repo.get_by_email(user_info["email"])
                    if not user.oauth_id:
                        user = await self._user_repo.link_oauth_account(
                            user_id=user.id,
                            provider=provider,
                            oauth_id=user_info["sub"],
                        )
                except NotFoundError:
                    user = await self._user_repo.create_oauth_user(
                        email=user_info["email"],
                        provider=provider,
                        oauth_id=user_info["sub"],
                        is_verified=user_info.get("email_verified", False),
                        role=UserRole.USER,
                    )

            tokens = await self._token_service.create_tokens(
                user_id=user.id,
                user_agent=request.headers.get("user-agent", ""),
                ip_address=get_client_ip(request),
                request=request,
                response=response,
            )

            audit_service = AuditService(self._audit_repo)
            await audit_service.create_log(
                AuditLogCreate(
                    user_id=user.id,
                    action=f"login_{provider}",
                    ip_address=get_client_ip(request),
                    user_agent=request.headers.get("user-agent", ""),
                    details=f"Logged in with {provider}",
                )
            )

            # For web clients
            if tokens is None:
                return TokenResponse(
                    access_token=cast(str, request.session.get("access_token")),
                    refresh_token=None,
                    token_type="bearer",
                    expires_in=settings.JWT_ACCESS_TOKEN_TTL_SECS,
                )

            # For API clients
            return tokens

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
            user = await self._user_repo.get_by_email(email.lower())

            reset_token = token_hex(32)
            reset_token_expires = datetime.now(UTC) + timedelta(
                seconds=settings.VERIFICATION_CODE_TTL_SECS,
            )

            # Update user with reset token first
            await self._user_repo.update(
                user.id,
                {
                    "reset_token": reset_token,
                    "reset_token_expires_at": reset_token_expires,
                },
            )

            # Log the action
            audit_service = AuditService(self._audit_repo)
            await audit_service.create_log(
                AuditLogCreate(
                    user_id=user.id,
                    action="password_reset_request",
                    ip_address=get_client_ip(request),
                    user_agent=request.headers.get("user-agent", ""),
                    details="Password reset requested",
                )
            )

            # Attempt to send email but don't roll back if it fails
            try:
                reset_url = f"{settings.FRONTEND_URL.unicode_string()}{settings.PASSWORD_RESET_URI}?token={reset_token}"
                await email_service.send_password_reset_email(user.email, reset_url)
            except Exception as e:
                logger.error("Failed to send password reset email: %s", str(e))
                # Log the email failure but don't raise
                await audit_service.create_log(
                    AuditLogCreate(
                        user_id=user.id,
                        action="password_reset_email",
                        ip_address=get_client_ip(request),
                        user_agent=request.headers.get("user-agent", ""),
                        details=f"Failed to send password reset email: {str(e)}",
                    )
                )

        except NotFoundError:
            # Silently pass for non-existent emails to prevent enumeration
            pass
        except Exception as e:
            logger.error("Password reset request failed: %s", str(e))
            raise AuthError("Failed to process password reset request")

    async def verify_password_reset(
        self,
        request: Request,
        reset_data: PasswordResetVerify,
    ) -> None:
        """Verify password reset token and update password.

        Args:
            request: FastAPI request
            reset_data: Password reset verification data

        Raises:
            AuthError: If verification fails
        """
        try:
            user = await self._user_repo.get_by_reset_token(reset_data.token)

            await self._user_repo.update(
                user.id,
                {
                    "password_hash": get_password_hash(reset_data.password),
                    "reset_token": None,
                    "reset_token_expires_at": None,
                },
            )

            await self._token_service.revoke_all_user_tokens(user.id.hex)

            audit_service = AuditService(self._audit_repo)
            await audit_service.create_log(
                AuditLogCreate(
                    user_id=user.id,
                    action="password_reset",
                    ip_address=get_client_ip(request),
                    user_agent=request.headers.get("user-agent", ""),
                    details="Password reset successful",
                )
            )

        except NotFoundError:
            raise AuthError("Invalid or expired reset token")
        except Exception as e:
            logger.error("Password reset verification failed: %s", str(e))
            raise AuthError("Failed to reset password")

    async def _create_oauth_user(
        self,
        request: Request,
        email: str,
        provider: str,
        oauth_id: str,
    ) -> User:
        """Create a new user from OAuth login.

        Args:
            request: FastAPI request
            email: User's email address
            provider: OAuth provider name
            oauth_id: Provider's user ID

        Returns:
            Created user

        Raises:
            AuthError: If user creation fails
        """
        try:
            user = await self._user_repo.create_oauth_user(
                email=email,
                provider=provider,
                oauth_id=oauth_id,
                is_verified=True,
                role=UserRole.USER,
            )

            audit_service = AuditService(self._audit_repo)
            await audit_service.create_log(
                AuditLogCreate(
                    user_id=user.id,
                    action="oauth_register",
                    ip_address=get_client_ip(request),
                    user_agent=request.headers.get("user-agent", ""),
                    details=f"OAuth registration successful via {provider}",
                )
            )

            return user

        except Exception as e:
            logger.error("OAuth registration failed: %s", str(e))
            raise AuthError("Failed to register user")

    async def _link_oauth_account(
        self,
        request: Request,
        user: User,
        provider: str,
        oauth_id: str,
    ) -> User:
        """Link OAuth account to existing user.

        Args:
            request: FastAPI request
            user: User to link account to
            provider: OAuth provider name
            oauth_id: Provider's user ID

        Returns:
            Updated user

        Raises:
            AuthError: If account linking fails
            DuplicateError: If OAuth account already linked
        """
        try:
            try:
                existing_user = await self._user_repo.get_by_oauth_id(
                    provider, oauth_id
                )
                if existing_user.id != user.id:
                    raise DuplicateError("OAuth account already linked to another user")
            except NotFoundError:
                pass

            updated_user = await self._user_repo.update(
                user.id,
                {
                    "oauth_provider": provider,
                    "oauth_id": oauth_id,
                },
            )

            audit_service = AuditService(self._audit_repo)
            await audit_service.create_log(
                AuditLogCreate(
                    user_id=user.id,
                    action="oauth_link",
                    ip_address=get_client_ip(request),
                    user_agent=request.headers.get("user-agent", ""),
                    details=f"OAuth account linked via {provider}",
                )
            )

            return updated_user

        except DuplicateError:
            raise
        except Exception as e:
            logger.error("OAuth account linking failed: %s", str(e))
            raise AuthError("Failed to link OAuth account")

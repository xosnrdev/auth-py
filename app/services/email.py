"""Secure transactional email service with TLS and template support."""

import asyncio
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Final
from urllib.parse import urljoin

import aiosmtplib
from pydantic import EmailStr, SecretStr

from app.core.config import settings

logger = logging.getLogger(__name__)

MAX_SUBJECT_LENGTH: Final[int] = 78
MAX_RETRIES: Final[int] = 3
RETRY_DELAY_SECONDS: Final[int] = 1
MIME_TYPE_PLAIN: Final[str] = "plain"
MIME_TYPE_HTML: Final[str] = "html"
MIME_TYPE_ALTERNATIVE: Final[str] = "alternative"


class EmailError(Exception):
    """Base exception for email service errors."""

    def __init__(self, message: str, detail: str | None = None) -> None:
        """Initialize with user-safe message and optional detail for logging."""
        self.message = message
        self.detail = detail or message
        super().__init__(self.message)


class EmailService:
    """Async email service with secure SMTP delivery and templates."""

    def __init__(self) -> None:
        """Initialize with SMTP settings from environment."""
        try:
            assert settings.SMTP_HOST, "SMTP_HOST must be set"
            assert settings.SMTP_PORT, "SMTP_PORT must be set"
            assert settings.SMTP_USER, "SMTP_USER must be set"
            assert settings.SMTP_PASSWORD, "SMTP_PASSWORD must be set"
            assert settings.SMTP_FROM_EMAIL, "SMTP_FROM_EMAIL must be set"
            assert settings.SMTP_FROM_NAME, "SMTP_FROM_NAME must be set"

            self.host: str = settings.SMTP_HOST
            self.port: int = settings.SMTP_PORT
            self.username: str = settings.SMTP_USER
            self.password: SecretStr = settings.SMTP_PASSWORD
            self.from_email: EmailStr = settings.SMTP_FROM_EMAIL
            self.from_name: str = settings.SMTP_FROM_NAME

        except AssertionError as e:
            logger.error("Email service configuration error: %s", str(e))
            raise EmailError(
                message="Email service configuration error",
                detail=f"Configuration error: {str(e)}",
            )
        except Exception as e:
            logger.error(
                "Unexpected error during email service initialization: %s", str(e)
            )
            raise EmailError(
                message="Email service initialization failed",
                detail=f"Initialization error: {str(e)}",
            )

    async def _send_email(
        self,
        to_email: EmailStr,
        subject: str,
        html_content: str,
        text_content: str,
    ) -> None:
        """Send email with retry logic."""
        try:
            assert len(subject) <= MAX_SUBJECT_LENGTH, (
                f"Subject exceeds {MAX_SUBJECT_LENGTH} chars"
            )
            assert html_content, "HTML content required"
            assert text_content, "Text content required"

            msg = MIMEMultipart(MIME_TYPE_ALTERNATIVE)
            msg["Subject"] = subject
            msg["From"] = f"{self.from_name} <{self.from_email}>"
            msg["To"] = str(to_email)
            msg.attach(MIMEText(text_content, MIME_TYPE_PLAIN))
            msg.attach(MIMEText(html_content, MIME_TYPE_HTML))

            last_error: Exception | None = None
            for attempt in range(MAX_RETRIES):
                try:
                    async with aiosmtplib.SMTP(
                        hostname=self.host,
                        port=self.port,
                        use_tls=True,
                    ) as smtp:
                        await smtp.login(
                            self.username, self.password.get_secret_value()
                        )
                        await smtp.send_message(msg)
                        logger.info("Email sent to %s", to_email)
                        return
                except aiosmtplib.SMTPAuthenticationError as e:
                    logger.error("SMTP authentication failed: %s", str(e))
                    raise EmailError(
                        message="Email service authentication failed",
                        detail=f"SMTP auth error: {str(e)}",
                    )
                except Exception as e:
                    last_error = e
                    logger.warning(
                        "Attempt %d: Failed to send email to %s: %s",
                        attempt + 1,
                        to_email,
                        str(e),
                    )
                    if attempt < MAX_RETRIES - 1:
                        await asyncio.sleep(RETRY_DELAY_SECONDS)

            assert last_error is not None
            logger.error(
                "Email sending failed after %d attempts: %s",
                MAX_RETRIES,
                str(last_error),
            )
            raise EmailError(
                message="Failed to send email",
                detail=f"Failed after {MAX_RETRIES} attempts: {str(last_error)}",
            )

        except AssertionError as e:
            logger.error("Email validation error: %s", str(e))
            raise EmailError(
                message="Email validation failed", detail=f"Validation error: {str(e)}"
            )
        except EmailError:
            raise
        except Exception as e:
            logger.error("Unexpected error during email sending: %s", str(e))
            raise EmailError(
                message="Failed to send email", detail=f"Unexpected error: {str(e)}"
            )

    async def send_verification_email(
        self,
        to_email: EmailStr,
        verification_code: str,
    ) -> None:
        """Send email verification link."""
        assert verification_code, "Verification code required"
        verification_url = urljoin(
            settings.FRONTEND_URL.unicode_string(),
            f"{settings.VERIFICATION_URI}?code={verification_code}",
        )

        text_content = (
            f"Please verify your email:\n"
            f"{verification_url}\n\n"
            f"Link expires in {settings.VERIFICATION_CODE_TTL_SECS} hours.\n\n"
            f"If you didn't request this, ignore this email."
        )

        html_content = (
            f"<h2>Verify Your Email</h2>"
            f"<p><a href='{verification_url}'>Click to Verify Email</a></p>"
            f"<p>Link expires in {settings.VERIFICATION_CODE_TTL_SECS} hours.</p>"
            f"<p>If you didn't request this, ignore this email.</p>"
        )

        await self._send_email(
            to_email=to_email,
            subject="Verify your email",
            html_content=html_content,
            text_content=text_content,
        )

    async def send_password_reset_email(
        self,
        to_email: EmailStr,
        reset_token: str,
    ) -> None:
        """Send password reset link."""
        assert reset_token, "Reset token required"

        reset_url = urljoin(
            settings.FRONTEND_URL.unicode_string(),
            f"{settings.PASSWORD_RESET_URI}?token={reset_token}",
        )

        text_content = (
            f"Reset your password:\n"
            f"{reset_url}\n\n"
            f"Link expires in {settings.VERIFICATION_CODE_TTL_SECS} hours.\n\n"
            f"If you didn't request this, change your password immediately."
        )

        html_content = (
            f"<h2>Reset Your Password</h2>"
            f"<p><a href='{reset_url}'>Click to Reset Password</a></p>"
            f"<p>Link expires in {settings.VERIFICATION_CODE_TTL_SECS} hours.</p>"
            f"<p>If you didn't request this, change your password immediately.</p>"
        )

        await self._send_email(
            to_email=to_email,
            subject="Reset your password",
            html_content=html_content,
            text_content=text_content,
        )

    async def send_email_change_notification(
        self,
        to_email: EmailStr,
        new_email: str,
    ) -> None:
        """Send notification about email address change."""
        assert new_email, "New email required"

        text_content = (
            f"Your email address has been changed to {new_email}.\n\n"
            f"If you did not request this change, please contact support immediately."
        )

        html_content = (
            f"<h2>Email Address Changed</h2>"
            f"<p>Your email address has been changed to <strong>{new_email}</strong>.</p>"
            f"<p>If you did not request this change, please contact support immediately.</p>"
        )

        await self._send_email(
            to_email=to_email,
            subject="Email Address Changed",
            html_content=html_content,
            text_content=text_content,
        )


email_service = EmailService()

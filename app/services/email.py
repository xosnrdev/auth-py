"""Secure transactional email service with TLS and template support.

Example:
```python
# Initialize service
email_svc = EmailService()

# Send verification email
await email_svc.send_verification_email(
    to_email="user@example.com",
    verification_code="abc123"  # From your token generator
)

# Send password reset
await email_svc.send_password_reset_email(
    to_email="user@example.com",
    reset_token="xyz789"  # From your token generator
)
```

Critical Notes:
- Requires SMTP with TLS (port 587 or 465)
- Set all SMTP_* environment variables before use
- URLs must be HTTPS in production
- Tokens should have < 24h expiry
"""

import asyncio
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Final
from urllib.parse import urljoin

import aiosmtplib
from pydantic import EmailStr, SecretStr

from app.core.config import settings

# Initialize logger
logger = logging.getLogger(__name__)

# Constants
MAX_SUBJECT_LENGTH: Final[int] = 78
MAX_RETRIES: Final[int] = 3
RETRY_DELAY_SECONDS: Final[int] = 1
MIME_TYPE_PLAIN: Final[str] = "plain"
MIME_TYPE_HTML: Final[str] = "html"
MIME_TYPE_ALTERNATIVE: Final[str] = "alternative"


class EmailService:
    """Async email service with secure SMTP delivery and templates."""

    def __init__(self) -> None:
        """Initialize with SMTP settings from environment."""
        # Assert required settings
        assert settings.SMTP_HOST, "SMTP_HOST must be set"
        assert settings.SMTP_PORT, "SMTP_PORT must be set"
        assert settings.SMTP_USER, "SMTP_USER must be set"
        assert settings.SMTP_PASSWORD, "SMTP_PASSWORD must be set"
        assert settings.SMTP_FROM_EMAIL, "SMTP_FROM_EMAIL must be set"
        assert settings.SMTP_FROM_NAME, "SMTP_FROM_NAME must be set"
        assert settings.APP_URL.startswith("https://") or settings.APP_URL.startswith("http://localhost"), (
            "APP_URL must use HTTPS in production"
        )

        self.host: str = settings.SMTP_HOST
        self.port: int = settings.SMTP_PORT
        self.username: str = settings.SMTP_USER
        self.password: SecretStr = settings.SMTP_PASSWORD
        self.from_email: EmailStr = settings.SMTP_FROM_EMAIL
        self.from_name: str = settings.SMTP_FROM_NAME

    async def _send_email(
        self,
        to_email: EmailStr,
        subject: str,
        html_content: str,
        text_content: str,
    ) -> None:
        """Send email with retry logic.

        Args:
            to_email: Recipient email
            subject: Email subject
            html_content: HTML version
            text_content: Plain text version

        Raises:
            RuntimeError: If sending fails after retries
        """
        # Validate inputs
        assert len(subject) <= MAX_SUBJECT_LENGTH, f"Subject exceeds {MAX_SUBJECT_LENGTH} chars"
        assert html_content, "HTML content required"
        assert text_content, "Text content required"

        # Create message
        msg = MIMEMultipart(MIME_TYPE_ALTERNATIVE)
        msg["Subject"] = subject
        msg["From"] = f"{self.from_name} <{self.from_email}>"
        msg["To"] = str(to_email)
        msg.attach(MIMEText(text_content, MIME_TYPE_PLAIN))
        msg.attach(MIMEText(html_content, MIME_TYPE_HTML))

        # Send with retries
        last_error: Exception | None = None
        for attempt in range(MAX_RETRIES):
            try:
                async with aiosmtplib.SMTP(
                    hostname=self.host,
                    port=self.port,
                    use_tls=True,
                ) as smtp:
                    await smtp.login(self.username, self.password.get_secret_value())
                    await smtp.send_message(msg)
                    logger.info("Email sent to %s", to_email)
                    return
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
        raise RuntimeError(f"Failed to send email after {MAX_RETRIES} attempts") from last_error

    async def send_verification_email(
        self,
        to_email: EmailStr,
        verification_code: str,
    ) -> None:
        """Send email verification link.

        Args:
            to_email: User's email
            verification_code: Secure token

        Raises:
            RuntimeError: If sending fails
        """
        # Validate inputs
        assert verification_code, "Verification code required"

        # Generate URL
        verification_url = urljoin(
            settings.APP_URL,
            f"{settings.VERIFICATION_URL_PATH}?code={verification_code}",
        )

        # Create content
        text_content = (
            f"Please verify your email:\n"
            f"{verification_url}\n\n"
            f"Link expires in {settings.VERIFICATION_CODE_EXPIRES_HOURS} hours.\n\n"
            f"If you didn't request this, ignore this email."
        )

        html_content = (
            f"<h2>Verify Your Email</h2>"
            f"<p><a href='{verification_url}'>Click to Verify Email</a></p>"
            f"<p>Link expires in {settings.VERIFICATION_CODE_EXPIRES_HOURS} hours.</p>"
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
        """Send password reset link.

        Args:
            to_email: User's email
            reset_token: Secure token

        Raises:
            RuntimeError: If sending fails
        """
        # Validate inputs
        assert reset_token, "Reset token required"

        # Generate URL
        reset_url = urljoin(
            settings.APP_URL,
            f"{settings.PASSWORD_RESET_URL_PATH}?token={reset_token}",
        )

        # Create content
        text_content = (
            f"Reset your password:\n"
            f"{reset_url}\n\n"
            f"Link expires in {settings.VERIFICATION_CODE_EXPIRES_HOURS} hours.\n\n"
            f"If you didn't request this, change your password immediately."
        )

        html_content = (
            f"<h2>Reset Your Password</h2>"
            f"<p><a href='{reset_url}'>Click to Reset Password</a></p>"
            f"<p>Link expires in {settings.VERIFICATION_CODE_EXPIRES_HOURS} hours.</p>"
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
        """Send notification about email address change.

        Args:
            to_email: Old email address
            new_email: New email address

        Raises:
            RuntimeError: If sending fails
        """
        # Validate inputs
        assert new_email, "New email required"

        # Create content
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

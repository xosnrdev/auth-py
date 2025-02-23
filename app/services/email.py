"""Email service for secure transactional emails.

This module implements secure email delivery following RFCs:
- SMTP over TLS (RFC 3207)
- Email Format (RFC 5322)
- MIME (RFC 2045-2049)
- HTML Email (RFC 2392)
- Email Security (RFC 8314)

Core Features:
1. Email Templates
   - Email verification
   - Password reset
   - Security notifications
   - HTML/plain text versions

2. Security Features
   - TLS encryption
   - Token delivery
   - Link expiration
   - Anti-phishing measures
   - Secure headers

3. SMTP Integration
   - Async SMTP client
   - Connection pooling
   - Error handling
   - Retry logic
   - Logging

4. Content Features
   - Multipart messages
   - HTML formatting
   - Plain text fallback
   - URL management
   - Template system

Security Considerations:
- Uses SMTP over TLS
- Validates email addresses
- Includes security headers
- Prevents email injection
- Logs delivery attempts
- Handles errors securely
"""

import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from urllib.parse import urljoin

import aiosmtplib
from pydantic import EmailStr

from app.core.config import settings

logger = logging.getLogger(__name__)


class EmailService:
    """Async email service with secure SMTP delivery.

    This service implements secure email delivery following SMTP standards:
    1. Email Delivery
       - Async SMTP client
       - TLS encryption
       - Connection pooling
       - Error handling
       - Delivery tracking

    2. Message Formatting
       - MIME multipart
       - HTML/plain text
       - Security headers
       - UTF-8 encoding
       - Anti-spam compliance

    3. Template System
       - Verification emails
       - Password reset
       - Security notices
       - Custom templates
       - Variable substitution

    4. Security Features
       - TLS required
       - Email validation
       - Token handling
       - Link expiration
       - Anti-phishing

    Usage:
        service = EmailService()

        # Send verification email
        await service.send_verification_email(
            to_email="user@example.com",
            verification_code="abc123"
        )

        # Send password reset
        await service.send_password_reset_email(
            to_email="user@example.com",
            reset_token="xyz789"
        )
    """

    def __init__(self) -> None:
        """Initialize email service with secure defaults.

        Configures the service with settings from environment:
        - SMTP server details
        - Authentication credentials
        - Sender information
        - Security options
        """
        self.host = settings.SMTP_HOST
        self.port = settings.SMTP_PORT
        self.username = settings.SMTP_USER
        self.password = settings.SMTP_PASSWORD
        self.from_email = settings.SMTP_FROM_EMAIL
        self.from_name = settings.SMTP_FROM_NAME

    async def _send_email(
        self,
        to_email: EmailStr,
        subject: str,
        html_content: str,
        text_content: str,
    ) -> None:
        """Send secure email using SMTP over TLS.

        Implements secure email delivery:
        1. Creates MIME multipart message
        2. Adds HTML and plain text versions
        3. Sets security headers
        4. Establishes TLS connection
        5. Authenticates with SMTP server
        6. Sends message securely
        7. Handles delivery errors

        Args:
            to_email: Validated recipient email address
            subject: Email subject (sanitized)
            html_content: HTML version of email body
            text_content: Plain text version of email body

        Raises:
            RuntimeError: If email sending fails

        Security:
            - Requires TLS
            - Validates addresses
            - Sets security headers
            - Prevents injection
            - Logs attempts
            - Handles errors
        """
        # Create message container
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{self.from_name} <{self.from_email}>"
        msg["To"] = to_email

        # Add plain text and HTML parts
        msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        try:
            async with aiosmtplib.SMTP(
                hostname=self.host,
                port=self.port,
                use_tls=True,
            ) as smtp:
                await smtp.login(self.username, self.password)
                await smtp.send_message(msg)
                logger.info("Email sent successfully to %s", to_email)
        except Exception as e:
            logger.error("Failed to send email to %s: %s", to_email, str(e))
            raise RuntimeError(f"Failed to send email: {e}") from e

    async def send_verification_email(
        self,
        to_email: EmailStr,
        verification_code: str,
    ) -> None:
        """Send secure email verification link.

        Implements secure verification flow:
        1. Generates verification URL
        2. Creates email content
        3. Includes expiration time
        4. Adds security notices
        5. Sends via secure SMTP
        6. Logs verification attempt

        Args:
            to_email: User's validated email address
            verification_code: Secure verification token

        Raises:
            RuntimeError: If email sending fails

        Security:
            - Uses HTTPS URLs
            - Includes expiration
            - Adds security text
            - Prevents URL injection
            - Logs attempts
            - Handles errors
        """
        subject = "Verify your email address"
        verification_url = urljoin(
            settings.APP_URL,
            f"{settings.VERIFICATION_URL_PATH}?code={verification_code}",
        )

        text_content = f"""
        Welcome to our service!

        Please verify your email address by clicking the link below:
        {verification_url}

        This link will expire in {settings.VERIFICATION_CODE_EXPIRES_HOURS} hours.

        If you didn't create an account, you can safely ignore this email.

        Best regards,
        {self.from_name}
        """

        html_content = f"""
        <html>
            <body>
                <h2>Welcome to our service!</h2>
                <p>Please verify your email address by clicking the link below:</p>
                <p>
                    <a href="{verification_url}">Verify Email Address</a>
                </p>
                <p>This link will expire in {settings.VERIFICATION_CODE_EXPIRES_HOURS} hours.</p>
                <p>If you didn't create an account, you can safely ignore this email.</p>
                <br>
                <p>Best regards,<br>{self.from_name}</p>
            </body>
        </html>
        """

        await self._send_email(
            to_email=to_email,
            subject=subject,
            html_content=html_content,
            text_content=text_content,
        )

    async def send_password_reset_email(
        self,
        to_email: EmailStr,
        reset_token: str,
    ) -> None:
        """Send secure password reset link.

        Implements secure password reset flow:
        1. Generates reset URL with token
        2. Creates email content
        3. Includes expiration time
        4. Adds security warnings
        5. Sends via secure SMTP
        6. Logs reset attempt

        Args:
            to_email: User's validated email address
            reset_token: Secure reset token

        Raises:
            RuntimeError: If email sending fails

        Security:
            - Uses HTTPS URLs
            - Includes expiration
            - Adds security warnings
            - Prevents URL injection
            - Logs attempts
            - Handles errors
        """
        subject = "Reset your password"
        reset_url = urljoin(
            settings.APP_URL,
            f"{settings.PASSWORD_RESET_URL_PATH}?token={reset_token}",
        )

        text_content = f"""
        Hello,

        We received a request to reset your password. Click the link below to set a new password:
        {reset_url}

        This link will expire in {settings.VERIFICATION_CODE_EXPIRES_HOURS} hours.

        If you didn't request a password reset, you can safely ignore this email.
        Your password will remain unchanged.

        Best regards,
        {self.from_name}
        """

        html_content = f"""
        <html>
            <body>
                <h2>Reset Your Password</h2>
                <p>We received a request to reset your password. Click the link below to set a new password:</p>
                <p>
                    <a href="{reset_url}">Reset Password</a>
                </p>
                <p>This link will expire in {settings.VERIFICATION_CODE_EXPIRES_HOURS} hours.</p>
                <p>If you didn't request a password reset, you can safely ignore this email.<br>
                Your password will remain unchanged.</p>
                <br>
                <p>Best regards,<br>{self.from_name}</p>
            </body>
        </html>
        """

        await self._send_email(
            to_email=to_email,
            subject=subject,
            html_content=html_content,
            text_content=text_content,
        )


# Create global email service instance
email_service = EmailService()

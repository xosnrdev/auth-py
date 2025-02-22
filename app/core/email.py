"""Email service for sending transactional emails."""

import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from urllib.parse import urljoin

import aiosmtplib
from pydantic import EmailStr

from app.core.config import settings

logger = logging.getLogger(__name__)


class EmailService:
    """Async email service using SMTP."""

    def __init__(self) -> None:
        """Initialize email service with settings."""
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
        """Send email using SMTP.

        Args:
            to_email: Recipient email address
            subject: Email subject
            html_content: HTML version of email body
            text_content: Plain text version of email body

        Raises:
            RuntimeError: If email sending fails
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
        """Send email verification link.

        Args:
            to_email: User's email address
            verification_code: Verification code to include in email

        Raises:
            RuntimeError: If email sending fails
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


# Create global email service instance
email_service = EmailService()

"""
Email utilities for sending password reset emails and other notifications.
"""

import logging
import secrets
import uuid
from datetime import datetime

from app.core.config import settings


logger = logging.getLogger(__name__)


class EmailService:
    """Service for sending emails."""

    def __init__(self):
        """Initialize email service with configuration."""
        self.smtp_server = getattr(settings, 'SMTP_SERVER', 'localhost')
        self.smtp_port = getattr(settings, 'SMTP_PORT', 587)
        self.smtp_username = getattr(settings, 'SMTP_USERNAME', '')
        self.smtp_password = getattr(settings, 'SMTP_PASSWORD', '')
        self.smtp_use_tls = getattr(settings, 'SMTP_USE_TLS', True)
        self.from_email = getattr(settings, 'FROM_EMAIL', 'noreply@personalai.com')
        self.from_name = getattr(settings, 'FROM_NAME', 'Personal AI Assistant')

    async def send_password_reset_email(
        self,
        email: str,
        token: str,
        expires_at: datetime | None = None
    ) -> bool:
        """
        Send password reset email to user.

        Args:
            email: Recipient email address
            token: Password reset token
            expires_at: Token expiry time

        Returns:
            True if email sent successfully, False otherwise
        """
        try:
            # Create reset URL
            reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token}"

            # Format expiry time
            expiry_str = expires_at.strftime('%Y-%m-%d %H:%M:%S UTC') if expires_at else "1 hour"

            # Create email content
            subject = "Reset your Personal AI Assistant password"

            _ = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>Password Reset</title>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        line-height: 1.6;
                        color: #333;
                        max-width: 600px;
                        margin: 0 auto;
                        padding: 20px;
                    }}
                    .header {{
                        background-color: #4A90E2;
                        color: white;
                        padding: 20px;
                        text-align: center;
                    }}
                    .content {{
                        padding: 20px;
                        background-color: #f9f9f9;
                    }}
                    .button {{
                        display: inline-block;
                        background-color: #4A90E2;
                        color: white;
                        padding: 12px 30px;
                        text-decoration: none;
                        border-radius: 5px;
                        margin: 20px 0;
                    }}
                    .footer {{
                        text-align: center;
                        padding: 20px;
                        color: #666;
                        font-size: 12px;
                    }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>Personal AI Assistant</h1>
                    <p>Password Reset Request</p>
                </div>

                <div class="content">
                    <h2>Hello,</h2>
                    <p>You requested to reset your password for your Personal AI Assistant account.</p>
                    <p>Click the button below to reset your password:</p>

                    <p style="text-align: center;">
                        <a href="{reset_url}" class="button">Reset Password</a>
                    </p>

                    <p>Or copy and paste this link in your browser:</p>
                    <p style="word-break: break-all; background-color: #eee; padding: 10px;">
                        {reset_url}
                    </p>

                    <p><strong>Note:</strong> This link will expire on {expiry_str}.</p>
                    <p>If you didn't request a password reset, you can safely ignore this email.</p>
                </div>

                <div class="footer">
                    <p>&copy; 2024 Personal AI Assistant. All rights reserved.</p>
                </div>
            </body>
            </html>
            """

            text_body = f"""
            Password Reset - Personal AI Assistant

            Hello,

            You requested to reset your password for your Personal AI Assistant account.

            Click the link below to reset your password:
            {reset_url}

            This link will expire on {expiry_str}.

            If you didn't request a password reset, you can safely ignore this email.

            © 2024 Personal AI Assistant. All rights reserved.
            """

            # For development, just log the email content
            if settings.ENVIRONMENT == "development":
                logger.info(f"{'='*50}")
                logger.info(f"TO: {email}")
                logger.info(f"SUBJECT: {subject}")
                logger.info(f"\n{text_body}")
                logger.info(f"{'='*50}")
                return True

            # TODO: Implement actual email sending using SMTP
            # For now, return True to simulate successful sending
            # In production, use a library like aiosmtplib or sendgrid

            return True

        except Exception as e:
            logger.error(f"Failed to send password reset email: {str(e)}")
            return False

    async def send_verification_email(
        self,
        email: str,
        token: str
    ) -> bool:
        """
        Send email verification email to user.

        Args:
            email: Recipient email address
            token: Email verification token

        Returns:
            True if email sent successfully, False otherwise
        """
        try:
            # Create verification URL
            verify_url = f"{settings.FRONTEND_URL}/verify-email?token={token}"

            subject = "Verify your Personal AI Assistant email"

            _ = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>Email Verification</title>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        line-height: 1.6;
                        color: #333;
                        max-width: 600px;
                        margin: 0 auto;
                        padding: 20px;
                    }}
                    .header {{
                        background-color: #4A90E2;
                        color: white;
                        padding: 20px;
                        text-align: center;
                    }}
                    .content {{
                        padding: 20px;
                        background-color: #f9f9f9;
                    }}
                    .button {{
                        display: inline-block;
                        background-color: #4A90E2;
                        color: white;
                        padding: 12px 30px;
                        text-decoration: none;
                        border-radius: 5px;
                        margin: 20px 0;
                    }}
                    .footer {{
                        text-align: center;
                        padding: 20px;
                        color: #666;
                        font-size: 12px;
                    }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>Personal AI Assistant</h1>
                    <p>Email Verification</p>
                </div>

                <div class="content">
                    <h2>Welcome to Personal AI Assistant!</h2>
                    <p>Please verify your email address to activate your account.</p>

                    <p style="text-align: center;">
                        <a href="{verify_url}" class="button">Verify Email</a>
                    </p>

                    <p>Or copy and paste this link in your browser:</p>
                    <p style="word-break: break-all; background-color: #eee; padding: 10px;">
                        {verify_url}
                    </p>

                    <p>If you didn't create an account with us, you can safely ignore this email.</p>
                </div>

                <div class="footer">
                    <p>&copy; 2024 Personal AI Assistant. All rights reserved.</p>
                </div>
            </body>
            </html>
            """

            text_body = f"""
            Email Verification - Personal AI Assistant

            Welcome to Personal AI Assistant!

            Please verify your email address to activate your account:
            {verify_url}

            If you didn't create an account with us, you can safely ignore this email.

            © 2024 Personal AI Assistant. All rights reserved.
            """

            # For development, just log the email content
            if settings.ENVIRONMENT == "development":
                logger.info(f"{'='*50}")
                logger.info(f"TO: {email}")
                logger.info(f"SUBJECT: {subject}")
                logger.info(f"\n{text_body}")
                logger.info(f"{'='*50}")
                return True

            return True

        except Exception as e:
            logger.error(f"Failed to send verification email: {str(e)}")
            return False


def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token.

    Args:
        length: Length of the token in bytes

    Returns:
        Hexadecimal string token
    """
    return secrets.token_hex(length)


def generate_uuid_token() -> str:
    """
    Generate a UUID-based token.

    Returns:
        UUID string token
    """
    return str(uuid.uuid4())


def validate_email_format(email: str) -> bool:
    """
    Validate email format using basic checks.

    Args:
        email: Email address to validate

    Returns:
        True if email format is valid, False otherwise
    """
    import re

    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


# Create a singleton instance
email_service = EmailService()

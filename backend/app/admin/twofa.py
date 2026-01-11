"""Two-Factor Authentication utilities for admin panel."""

import io
import base64
import pyotp
import qrcode
from typing import Tuple


def generate_totp_secret() -> str:
    """
    Generate a new TOTP secret.

    Returns:
        Base32 encoded secret string
    """
    return pyotp.random_base32()


def generate_qr_code(username: str, secret: str, issuer: str = "Personal AI Assistant") -> str:
    """
    Generate QR code for TOTP setup.

    Args:
        username: User's username or email
        secret: TOTP secret (base32 encoded)
        issuer: Application name

    Returns:
        Base64 encoded PNG image of QR code
    """
    # Create provisioning URI
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=username,
        issuer_name=issuer
    )

    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    # Create image
    img = qr.make_image(fill_color="black", back_color="white")

    # Convert to base64
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    img_base64 = base64.b64encode(buffer.getvalue()).decode()

    return f"data:image/png;base64,{img_base64}"


def verify_totp_token(secret: str, token: str) -> bool:
    """
    Verify a TOTP token.

    Args:
        secret: TOTP secret (base32 encoded)
        token: 6-digit token from authenticator app

    Returns:
        True if token is valid, False otherwise
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=1)  # Allow 1 time step before/after


def get_current_totp_token(secret: str) -> str:
    """
    Get current TOTP token (for testing purposes).

    Args:
        secret: TOTP secret (base32 encoded)

    Returns:
        Current 6-digit token
    """
    totp = pyotp.TOTP(secret)
    return totp.now()

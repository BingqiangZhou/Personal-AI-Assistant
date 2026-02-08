"""Admin setup and authentication routes module.

This module contains all routes related to:
- First-run admin setup
- Login/logout
- Two-factor authentication (2FA)
"""

import logging

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.admin.csrf import generate_csrf_token, validate_csrf_token
from app.admin.dependencies import (
    admin_required,
    admin_required_no_2fa,
    create_admin_session,
)
from app.admin.first_run import check_admin_exists
from app.admin.routes._shared import get_templates
from app.admin.twofa import generate_qr_code, generate_totp_secret, verify_totp_token
from app.core.database import get_db_session
from app.core.security import get_password_hash
from app.domains.user.models import User, UserStatus


logger = logging.getLogger(__name__)

router = APIRouter()
templates = get_templates()


# ==================== First-Run Setup ====================


@router.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request):
    """Display first-run setup page."""
    # Check if admin already exists
    admin_exists = await check_admin_exists()
    if admin_exists:
        # Admin already exists, redirect to login
        return RedirectResponse(url="/super/login", status_code=303)

    # Generate CSRF token
    csrf_token = generate_csrf_token()

    response = templates.TemplateResponse(
        "setup.html",
        {"request": request, "csrf_token": csrf_token, "messages": []},
    )

    # Set CSRF token in cookie
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=3600,
    )

    return response


@router.post("/setup")
async def setup_admin(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    account_name: str | None = Form(None),
    csrf_token: str = Form(...),
    db: AsyncSession = Depends(get_db_session),
):
    """Create initial admin user."""
    try:
        # Check if admin already exists
        admin_exists = await check_admin_exists()
        if admin_exists:
            return RedirectResponse(url="/super/login", status_code=303)

        # Validate CSRF token
        validate_csrf_token(request, csrf_token)

        # Validate passwords match
        if password != password_confirm:
            csrf_token_new = generate_csrf_token()
            response = templates.TemplateResponse(
                "setup.html",
                {
                    "request": request,
                    "csrf_token": csrf_token_new,
                    "messages": [{"type": "error", "text": "两次输入的密码不一致"}],
                },
            )
            response.set_cookie(
                key="csrf_token",
                value=csrf_token_new,
                httponly=True,
                secure=True,
                samesite="lax",
                max_age=3600,
            )
            return response

        # Validate password length
        if len(password) < 8:
            csrf_token_new = generate_csrf_token()
            response = templates.TemplateResponse(
                "setup.html",
                {
                    "request": request,
                    "csrf_token": csrf_token_new,
                    "messages": [{"type": "error", "text": "密码长度至少为8个字符"}],
                },
            )
            response.set_cookie(
                key="csrf_token",
                value=csrf_token_new,
                httponly=True,
                secure=True,
                samesite="lax",
                max_age=3600,
            )
            return response

        # Check if username or email already exists
        result = await db.execute(
            select(User).where((User.username == username) | (User.email == email))
        )
        existing_user = result.scalar_one_or_none()

        if existing_user:
            csrf_token_new = generate_csrf_token()
            response = templates.TemplateResponse(
                "setup.html",
                {
                    "request": request,
                    "csrf_token": csrf_token_new,
                    "messages": [
                        {"type": "error", "text": "用户名或邮箱已存在"}
                    ],
                },
            )
            response.set_cookie(
                key="csrf_token",
                value=csrf_token_new,
                httponly=True,
                secure=True,
                samesite="lax",
                max_age=3600,
            )
            return response

        # Create admin user
        hashed_password = get_password_hash(password)
        admin_user = User(
            username=username,
            email=email,
            hashed_password=hashed_password,
            account_name=account_name or f"Admin {username}",
            status=UserStatus.ACTIVE,
            is_superuser=True,
            is_verified=True,
        )

        db.add(admin_user)
        await db.commit()
        await db.refresh(admin_user)

        logger.info(f"Initial admin user created: {username}")

        # Generate TOTP secret for 2FA setup
        totp_secret = generate_totp_secret()
        admin_user.totp_secret = totp_secret
        await db.commit()
        await db.refresh(admin_user)

        # Create session and redirect to 2FA setup
        session_token = create_admin_session(admin_user.id)

        response = RedirectResponse(url="/super/2fa/setup", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(
            key="admin_session",
            value=session_token,
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=30 * 60,  # 30 minutes
        )

        return response

    except Exception as e:
        logger.error(f"Setup error: {e}")
        csrf_token_new = generate_csrf_token()
        response = templates.TemplateResponse(
            "setup.html",
            {
                "request": request,
                "csrf_token": csrf_token_new,
                "messages": [{"type": "error", "text": "创建管理员失败，请稍后重试"}],
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
        response.set_cookie(
            key="csrf_token",
            value=csrf_token_new,
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=3600,
        )
        return response


# ==================== Login & Logout ====================


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = None):
    """Display login page."""
    # Generate CSRF token
    csrf_token = generate_csrf_token()

    # Convert error string to messages list format
    messages = [{"type": "error", "text": error}] if error else []

    response = templates.TemplateResponse(
        "login.html",
        {"request": request, "csrf_token": csrf_token, "messages": messages},
    )

    # Set CSRF token in cookie
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=3600,
    )

    return response


@router.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: AsyncSession = Depends(get_db_session),
):
    """Handle login."""
    try:
        # Validate CSRF token
        validate_csrf_token(request, csrf_token)

        # Get user
        result = await db.execute(select(User).where(User.username == username))
        user = result.scalar_one_or_none()

        if not user:
            csrf_token_new = generate_csrf_token()
            response = templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "csrf_token": csrf_token_new,
                    "messages": [{"type": "error", "text": "用户名或密码错误"}],
                },
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
            response.set_cookie(
                key="csrf_token",
                value=csrf_token_new,
                httponly=True,
                secure=True,
                samesite="lax",
                max_age=3600,
            )
            return response

        # Verify password
        from app.core.security import verify_password

        if not verify_password(password, user.hashed_password):
            csrf_token_new = generate_csrf_token()
            response = templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "csrf_token": csrf_token_new,
                    "messages": [{"type": "error", "text": "用户名或密码错误"}],
                },
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
            response.set_cookie(
                key="csrf_token",
                value=csrf_token_new,
                httponly=True,
                secure=True,
                samesite="lax",
                max_age=3600,
            )
            return response

        # Check if user has 2FA enabled AND global 2FA is enabled
        # 检查用户是否启用2FA 且 全局2FA已启用
        from app.admin.security_settings import get_admin_2fa_enabled
        admin_2fa_enabled, _ = await get_admin_2fa_enabled(db)

        if user.is_2fa_enabled and admin_2fa_enabled:
            # User has 2FA enabled, require verification
            # 用户已启用2FA，要求验证
            response = templates.TemplateResponse(
                "2fa_verify.html",
                {
                    "request": request,
                    "user": None,
                    "username": username,
                    "csrf_token": csrf_token,
                    "messages": [],
                },
            )
            response.set_cookie(
                key="2fa_user_id",
                value=str(user.id),
                httponly=True,
                secure=True,
                samesite="lax",
                max_age=5 * 60,  # 5 minutes
            )
            return response
        else:
            # Check if global 2FA is enabled but user hasn't set up 2FA
            # 检查全局2FA是否开启但用户未设置2FA
            if admin_2fa_enabled and not user.is_2fa_enabled:
                # Create session first (user is authenticated)
                session_token = create_admin_session(user.id)
                # Then redirect to 2FA setup (will be enforced by AdminAuthRequired)
                response = RedirectResponse(url="/super/2fa/setup", status_code=status.HTTP_303_SEE_OTHER)
                response.set_cookie(
                    key="admin_session",
                    value=session_token,
                    httponly=True,
                    secure=True,
                    samesite="lax",
                    max_age=30 * 60,  # 30 minutes
                )
                logger.info(f"User {username} logged in but required to set up 2FA")
                return response

            # No 2FA required, create session directly
            session_token = create_admin_session(user.id)

            response = RedirectResponse(url="/super", status_code=status.HTTP_303_SEE_OTHER)
            response.set_cookie(
                key="admin_session",
                value=session_token,
                httponly=True,
                secure=True,
                samesite="lax",
                max_age=30 * 60,  # 30 minutes
            )

            # Log login with 2FA status
            if user.is_2fa_enabled and not admin_2fa_enabled:
                logger.info(f"User {username} logged in with 2FA enabled but global 2FA is disabled")
            elif not admin_2fa_enabled:
                logger.info(f"User {username} logged in without 2FA (global disabled)")
            else:
                logger.info(f"User {username} logged in without 2FA configured")
            return response

    except Exception as e:
        logger.error(f"Login error: {e}")
        csrf_token_new = generate_csrf_token()
        response = templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "csrf_token": csrf_token_new,
                "messages": [{"type": "error", "text": "登录失败，请稍后重试"}],
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
        response.set_cookie(
            key="csrf_token",
            value=csrf_token_new,
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=3600,
        )
        return response


@router.post("/logout")
async def logout():
    """Handle logout."""
    response = RedirectResponse(url="/super/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(key="admin_session")
    return response


# ==================== 2FA Routes ====================


@router.post("/login/2fa")
async def verify_2fa_login(
    request: Request,
    username: str = Form(...),
    token: str = Form(...),
    csrf_token: str = Form(...),
    db: AsyncSession = Depends(get_db_session),
):
    """Verify 2FA token during login."""
    try:
        # Validate CSRF token
        validate_csrf_token(request, csrf_token)

        # Get user_id from cookie
        user_id_str = request.cookies.get("2fa_user_id")
        if not user_id_str:
            return templates.TemplateResponse(
                "2fa_verify.html",
                {
                    "request": request,
                    "user": None,
                    "username": username,
                    "csrf_token": csrf_token,
                    "messages": [{"type": "error", "text": "会话已过期，请重新登录"}],
                },
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        user_id = int(user_id_str)

        # Get user
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()

        if not user or not user.totp_secret:
            return templates.TemplateResponse(
                "2fa_verify.html",
                {
                    "request": request,
                    "user": None,
                    "username": username,
                    "csrf_token": csrf_token,
                    "messages": [{"type": "error", "text": "用户未找到或未启用2FA"}],
                },
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        # Verify TOTP token
        if not verify_totp_token(user.totp_secret, token):
            return templates.TemplateResponse(
                "2fa_verify.html",
                {
                    "request": request,
                    "user": None,
                    "username": username,
                    "csrf_token": csrf_token,
                    "messages": [{"type": "error", "text": "验证码错误，请重试"}],
                },
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        # Create session
        session_token = create_admin_session(user.id)

        # Redirect to dashboard
        response = RedirectResponse(url="/super", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(
            key="admin_session",
            value=session_token,
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=30 * 60,  # 30 minutes
        )
        # Clear 2FA cookie
        response.delete_cookie(key="2fa_user_id")

        logger.info(f"User {username} completed 2FA login")
        return response

    except Exception as e:
        logger.error(f"2FA verification error: {e}")
        return templates.TemplateResponse(
            "2fa_verify.html",
            {
                "request": request,
                "user": None,
                "username": username,
                "csrf_token": csrf_token,
                "messages": [{"type": "error", "text": "验证失败，请稍后重试"}],
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@router.get("/2fa/setup", response_class=HTMLResponse)
async def setup_2fa_page(
    request: Request,
    user: User = Depends(admin_required_no_2fa),
    db: AsyncSession = Depends(get_db_session),
):
    """Display 2FA setup page."""
    try:
        # Generate new TOTP secret if not exists
        if not user.totp_secret:
            secret = generate_totp_secret()
            user.totp_secret = secret
            await db.commit()
            await db.refresh(user)
        else:
            secret = user.totp_secret

        # Generate QR code
        qr_code = generate_qr_code(user.username or user.email, secret)

        # Generate CSRF token
        csrf_token = generate_csrf_token()

        response = templates.TemplateResponse(
            "2fa_setup.html",
            {
                "request": request,
                "user": user,
                "qr_code": qr_code,
                "secret": secret,
                "csrf_token": csrf_token,
                "messages": [],
            },
        )

        response.set_cookie(
            key="csrf_token",
            value=csrf_token,
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=3600,
        )

        return response

    except Exception as e:
        logger.error(f"2FA setup page error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to load 2FA setup page",
        )


@router.post("/2fa/verify")
async def verify_2fa_setup(
    request: Request,
    token: str = Form(...),
    csrf_token: str = Form(...),
    user: User = Depends(admin_required_no_2fa),
    db: AsyncSession = Depends(get_db_session),
):
    """Verify and enable 2FA."""
    try:
        # Validate CSRF token
        validate_csrf_token(request, csrf_token)

        if not user.totp_secret:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="TOTP secret not found",
            )

        # Verify token
        if not verify_totp_token(user.totp_secret, token):
            # Generate new CSRF token
            new_csrf_token = generate_csrf_token()
            qr_code = generate_qr_code(user.username or user.email, user.totp_secret)

            response = templates.TemplateResponse(
                "2fa_setup.html",
                {
                    "request": request,
                    "user": user,
                    "qr_code": qr_code,
                    "secret": user.totp_secret,
                    "csrf_token": new_csrf_token,
                    "messages": [{"type": "error", "text": "验证码错误，请重试"}],
                },
            )
            response.set_cookie(
                key="csrf_token",
                value=new_csrf_token,
                httponly=True,
                secure=True,
                samesite="lax",
                max_age=3600,
            )
            return response

        # Enable 2FA
        user.is_2fa_enabled = True
        await db.commit()

        logger.info(f"User {user.username} enabled 2FA")

        # Redirect to dashboard
        return RedirectResponse(url="/super", status_code=status.HTTP_303_SEE_OTHER)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"2FA verification error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify 2FA",
        )


@router.post("/2fa/disable")
async def disable_2fa(
    request: Request,
    password: str = Form(...),
    csrf_token: str = Form(...),
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Disable 2FA for the current user."""
    try:
        # Validate CSRF token
        validate_csrf_token(request, csrf_token)

        # Verify password
        from app.core.security import verify_password

        if not verify_password(password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="密码错误",
            )

        # Disable 2FA
        user.is_2fa_enabled = False
        user.totp_secret = None
        await db.commit()

        logger.info(f"User {user.username} disabled 2FA")

        # Redirect to dashboard with success message
        return RedirectResponse(url="/super", status_code=status.HTTP_303_SEE_OTHER)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to disable 2FA: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to disable 2FA",
        )

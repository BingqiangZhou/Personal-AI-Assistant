"""Admin panel routes."""
import logging
import secrets
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.admin.dependencies import admin_required, admin_required_no_2fa, create_admin_session
from app.admin.schemas import AdminLoginForm
from app.admin.csrf import generate_csrf_token, validate_csrf_token
from app.admin.audit import log_admin_action
from app.admin.models import AdminAuditLog
from app.admin.twofa import generate_totp_secret, generate_qr_code, verify_totp_token
from app.admin.first_run import check_admin_exists
from app.core.database import get_db_session
from app.core.security import verify_password, get_password_hash
from app.domains.ai.models import AIModelConfig
from app.domains.subscription.models import Subscription
from app.domains.user.models import User, UserStatus
from app.domains.user.repositories import UserRepository

logger = logging.getLogger(__name__)

router = APIRouter()

# Setup Jinja2 templates
templates = Jinja2Templates(directory="app/admin/templates")

# Password context for hashing API keys
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


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
    account_name: Optional[str] = Form(None),
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
        from app.admin.twofa import generate_totp_secret
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
async def login_page(request: Request):
    """Display login page."""
    # Generate CSRF token
    csrf_token = generate_csrf_token()

    response = templates.TemplateResponse(
        "login.html",
        {"request": request, "user": None, "messages": [], "csrf_token": csrf_token},
    )

    # Set CSRF token in cookie
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=True,
        secure=True,  # Set to True in production with HTTPS
        samesite="lax",
        max_age=3600,  # 1 hour
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
    """Handle login form submission."""
    try:
        # Validate CSRF token
        validate_csrf_token(request, csrf_token)

        # Get user by username
        user_repo = UserRepository(db)
        user = await user_repo.get_by_username(username)

        if not user or not verify_password(password, user.hashed_password):
            return templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "user": None,
                    "messages": [{"type": "error", "text": "用户名或密码错误"}],
                },
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        if not user.is_active:
            return templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "user": None,
                    "messages": [{"type": "error", "text": "用户已被禁用"}],
                },
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        # Check if 2FA is enabled
        if user.is_2fa_enabled and user.totp_secret:
            # Redirect to 2FA verification page
            csrf_token_2fa = generate_csrf_token()
            response = templates.TemplateResponse(
                "2fa_verify.html",
                {
                    "request": request,
                    "user": None,
                    "username": username,
                    "csrf_token": csrf_token_2fa,
                    "messages": [],
                },
            )
            response.set_cookie(
                key="csrf_token",
                value=csrf_token_2fa,
                httponly=True,
                secure=True,
                samesite="lax",
                max_age=3600,
            )
            # Store user_id temporarily in session for 2FA verification
            response.set_cookie(
                key="2fa_user_id",
                value=str(user.id),
                httponly=True,
                secure=True,
                samesite="lax",
                max_age=300,  # 5 minutes
            )
            return response

        # Create session (no 2FA or 2FA not enabled)
        session_token = create_admin_session(user.id)

        # Redirect to dashboard with session cookie
        response = RedirectResponse(url="/super", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(
            key="admin_session",
            value=session_token,
            httponly=True,
            secure=True,  # Set to True in production with HTTPS
            samesite="lax",
            max_age=30 * 60,  # 30 minutes
        )

        logger.info(f"User {username} logged in to admin panel")
        return response

    except Exception as e:
        logger.error(f"Login error: {e}")
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "user": None,
                "messages": [{"type": "error", "text": "登录失败，请稍后重试"}],
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


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

        # Log audit action
        await log_admin_action(
            db=db,
            user_id=user.id,
            username=user.username,
            action="enable_2fa",
            resource_type="user",
            resource_id=user.id,
            resource_name=user.username,
            request=request,
        )

        # Redirect to dashboard with success message
        response = RedirectResponse(url="/super", status_code=status.HTTP_303_SEE_OTHER)
        return response

    except Exception as e:
        logger.error(f"2FA verification error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify 2FA",
        )


@router.post("/2fa/disable")
async def disable_2fa(
    request: Request,
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Disable 2FA for current user."""
    try:
        user.is_2fa_enabled = False
        user.totp_secret = None
        await db.commit()

        logger.info(f"User {user.username} disabled 2FA")

        # Log audit action
        await log_admin_action(
            db=db,
            user_id=user.id,
            username=user.username,
            action="disable_2fa",
            resource_type="user",
            resource_id=user.id,
            resource_name=user.username,
            request=request,
        )

        return Response(status_code=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Disable 2FA error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to disable 2FA",
        )


@router.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Display admin dashboard."""
    try:
        # Get statistics
        # Count API keys (AI Model Configs)
        apikey_count_query = select(func.count()).select_from(AIModelConfig)
        apikey_count_result = await db.execute(apikey_count_query)
        apikey_count = apikey_count_result.scalar() or 0

        # Count subscriptions
        subscription_count_query = select(func.count()).select_from(Subscription)
        subscription_count_result = await db.execute(subscription_count_query)
        subscription_count = subscription_count_result.scalar() or 0

        # Count users
        user_count_query = select(func.count()).select_from(User)
        user_count_result = await db.execute(user_count_query)
        user_count = user_count_result.scalar() or 0

        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "user": user,
                "apikey_count": apikey_count,
                "subscription_count": subscription_count,
                "user_count": user_count,
                "messages": [],
            },
        )
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to load dashboard",
        )


# ==================== API Key Management ====================


@router.get("/apikeys", response_class=HTMLResponse)
async def apikeys_page(
    request: Request,
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Display API keys management page."""
    try:
        # Get all AI Model Configs (which contain API keys)
        result = await db.execute(
            select(AIModelConfig).order_by(AIModelConfig.created_at.desc())
        )
        apikeys = result.scalars().all()

        return templates.TemplateResponse(
            "apikeys.html",
            {
                "request": request,
                "user": user,
                "apikeys": apikeys,
                "messages": [],
            },
        )
    except Exception as e:
        logger.error(f"API keys page error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to load API keys",
        )


@router.post("/apikeys/create")
async def create_apikey(
    request: Request,
    name: str = Form(...),
    display_name: str = Form(...),
    model_type: str = Form(...),
    api_url: str = Form(...),
    model_id: str = Form(...),
    provider: str = Form(default="custom"),
    description: Optional[str] = Form(None),
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Create a new AI Model Config with API key."""
    try:
        # Generate a random API key
        api_key = f"pak_{secrets.token_urlsafe(32)}"  # pak = Personal AI Key

        # Encrypt the API key
        encrypted_key = pwd_context.hash(api_key)

        # Create AI Model Config
        new_config = AIModelConfig(
            name=name,
            display_name=display_name,
            description=description,
            model_type=model_type,
            api_url=api_url,
            api_key=encrypted_key,
            api_key_encrypted=True,
            model_id=model_id,
            provider=provider,
            is_active=True,
        )
        db.add(new_config)
        await db.commit()
        await db.refresh(new_config)

        logger.info(f"AI Model Config created: {name} by user {user.username}")

        # Log audit action
        await log_admin_action(
            db=db,
            user_id=user.id,
            username=user.username,
            action="create",
            resource_type="apikey",
            resource_id=new_config.id,
            resource_name=display_name,
            details={
                "name": name,
                "model_type": model_type,
                "provider": provider,
            },
            request=request,
        )

        # Return the new row HTML with the plain API key shown once
        return templates.TemplateResponse(
            "apikeys.html",
            {
                "request": request,
                "user": user,
                "apikeys": [new_config],
                "messages": [
                    {
                        "type": "success",
                        "text": f"API Key已创建: {api_key} (请立即复制保存，之后无法再次查看)",
                    }
                ],
                "show_plain_key": api_key,
            },
        )
    except Exception as e:
        logger.error(f"Create API key error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create API key",
        )


@router.put("/apikeys/{key_id}/toggle")
async def toggle_apikey(
    key_id: int,
    request: Request,
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Toggle AI Model Config active status."""
    try:
        result = await db.execute(
            select(AIModelConfig).where(AIModelConfig.id == key_id)
        )
        model_config = result.scalar_one_or_none()

        if not model_config:
            raise HTTPException(status_code=404, detail="API key not found")

        model_config.is_active = not model_config.is_active
        await db.commit()
        await db.refresh(model_config)

        logger.info(
            f"AI Model Config {key_id} toggled to {model_config.is_active} by user {user.username}"
        )

        # Log audit action
        await log_admin_action(
            db=db,
            user_id=user.id,
            username=user.username,
            action="toggle",
            resource_type="apikey",
            resource_id=key_id,
            resource_name=model_config.display_name,
            details={"is_active": model_config.is_active},
            request=request,
        )

        # Return updated row HTML
        return templates.TemplateResponse(
            "apikeys.html",
            {
                "request": request,
                "user": user,
                "apikeys": [model_config],
                "messages": [],
            },
        )
    except Exception as e:
        logger.error(f"Toggle API key error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to toggle API key",
        )


@router.delete("/apikeys/{key_id}/delete")
async def delete_apikey(
    key_id: int,
    request: Request,
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Delete an AI Model Config."""
    try:
        result = await db.execute(
            select(AIModelConfig).where(AIModelConfig.id == key_id)
        )
        model_config = result.scalar_one_or_none()

        if not model_config:
            raise HTTPException(status_code=404, detail="API key not found")

        # Store name before deletion
        resource_name = model_config.display_name

        await db.delete(model_config)
        await db.commit()

        logger.info(f"AI Model Config {key_id} deleted by user {user.username}")

        # Log audit action
        await log_admin_action(
            db=db,
            user_id=user.id,
            username=user.username,
            action="delete",
            resource_type="apikey",
            resource_id=key_id,
            resource_name=resource_name,
            request=request,
        )

        # Return empty response (htmx will remove the row)
        return Response(status_code=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Delete API key error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete API key",
        )


# ==================== RSS Subscription Management ====================


@router.get("/subscriptions", response_class=HTMLResponse)
async def subscriptions_page(
    request: Request,
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Display RSS subscriptions management page."""
    try:
        # Get all subscriptions
        result = await db.execute(
            select(Subscription).order_by(Subscription.created_at.desc())
        )
        subscriptions = result.scalars().all()

        return templates.TemplateResponse(
            "subscriptions.html",
            {
                "request": request,
                "user": user,
                "subscriptions": subscriptions,
                "messages": [],
            },
        )
    except Exception as e:
        logger.error(f"Subscriptions page error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to load subscriptions",
        )


@router.put("/subscriptions/{sub_id}/edit")
async def edit_subscription(
    sub_id: int,
    request: Request,
    title: Optional[str] = Form(None),
    feed_url: Optional[str] = Form(None),
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Edit a subscription."""
    try:
        result = await db.execute(select(Subscription).where(Subscription.id == sub_id))
        subscription = result.scalar_one_or_none()

        if not subscription:
            raise HTTPException(status_code=404, detail="Subscription not found")

        # Update fields
        if title is not None:
            subscription.title = title
        if feed_url is not None:
            subscription.feed_url = feed_url

        await db.commit()
        await db.refresh(subscription)

        logger.info(f"Subscription {sub_id} edited by user {user.username}")

        # Return updated row HTML
        return templates.TemplateResponse(
            "subscriptions.html",
            {
                "request": request,
                "user": user,
                "subscriptions": [subscription],
                "messages": [],
            },
        )
    except Exception as e:
        logger.error(f"Edit subscription error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to edit subscription",
        )


@router.delete("/subscriptions/{sub_id}/delete")
async def delete_subscription(
    sub_id: int,
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Delete a subscription."""
    try:
        result = await db.execute(select(Subscription).where(Subscription.id == sub_id))
        subscription = result.scalar_one_or_none()

        if not subscription:
            raise HTTPException(status_code=404, detail="Subscription not found")

        await db.delete(subscription)
        await db.commit()

        logger.info(f"Subscription {sub_id} deleted by user {user.username}")

        # Return empty response (htmx will remove the row)
        return Response(status_code=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Delete subscription error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete subscription",
        )


@router.post("/subscriptions/{sub_id}/refresh")
async def refresh_subscription(
    sub_id: int,
    request: Request,
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Manually refresh a subscription."""
    try:
        result = await db.execute(select(Subscription).where(Subscription.id == sub_id))
        subscription = result.scalar_one_or_none()

        if not subscription:
            raise HTTPException(status_code=404, detail="Subscription not found")

        # TODO: Trigger background task to refresh subscription
        # For now, just update the last_fetched_at timestamp
        from datetime import datetime
        subscription.last_fetched_at = datetime.utcnow()
        await db.commit()
        await db.refresh(subscription)

        logger.info(f"Subscription {sub_id} refresh triggered by user {user.username}")

        # Return updated row HTML
        return templates.TemplateResponse(
            "subscriptions.html",
            {
                "request": request,
                "user": user,
                "subscriptions": [subscription],
                "messages": [],
            },
        )
    except Exception as e:
        logger.error(f"Refresh subscription error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to refresh subscription",
        )


# ==================== Subscription Batch Operations ====================


@router.post("/subscriptions/batch/refresh")
async def batch_refresh_subscriptions(
    request: Request,
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Batch refresh subscriptions."""
    try:
        # Get IDs from request body
        body = await request.json()
        ids = body.get("ids", [])

        if not ids:
            raise HTTPException(status_code=400, detail="No subscription IDs provided")

        # Update last_fetched_at for all selected subscriptions
        from datetime import datetime
        result = await db.execute(
            select(Subscription).where(Subscription.id.in_(ids))
        )
        subscriptions = result.scalars().all()

        for subscription in subscriptions:
            subscription.last_fetched_at = datetime.utcnow()

        await db.commit()

        logger.info(f"Batch refresh {len(subscriptions)} subscriptions by user {user.username}")

        # Log audit action
        await log_admin_action(
            db=db,
            user_id=user.id,
            username=user.username,
            action="batch_refresh",
            resource_type="subscription",
            details={"count": len(subscriptions), "ids": ids},
            request=request,
        )

        return Response(status_code=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Batch refresh error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to batch refresh subscriptions",
        )


@router.post("/subscriptions/batch/toggle")
async def batch_toggle_subscriptions(
    request: Request,
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Batch toggle subscription status."""
    try:
        # Get IDs from request body
        body = await request.json()
        ids = body.get("ids", [])

        if not ids:
            raise HTTPException(status_code=400, detail="No subscription IDs provided")

        # Toggle is_active for all selected subscriptions
        result = await db.execute(
            select(Subscription).where(Subscription.id.in_(ids))
        )
        subscriptions = result.scalars().all()

        for subscription in subscriptions:
            subscription.is_active = not subscription.is_active

        await db.commit()

        logger.info(f"Batch toggle {len(subscriptions)} subscriptions by user {user.username}")

        # Log audit action
        await log_admin_action(
            db=db,
            user_id=user.id,
            username=user.username,
            action="batch_toggle",
            resource_type="subscription",
            details={"count": len(subscriptions), "ids": ids},
            request=request,
        )

        return Response(status_code=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Batch toggle error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to batch toggle subscriptions",
        )


@router.post("/subscriptions/batch/delete")
async def batch_delete_subscriptions(
    request: Request,
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Batch delete subscriptions."""
    try:
        # Get IDs from request body
        body = await request.json()
        ids = body.get("ids", [])

        if not ids:
            raise HTTPException(status_code=400, detail="No subscription IDs provided")

        # Delete all selected subscriptions
        result = await db.execute(
            select(Subscription).where(Subscription.id.in_(ids))
        )
        subscriptions = result.scalars().all()

        for subscription in subscriptions:
            await db.delete(subscription)

        await db.commit()

        logger.info(f"Batch delete {len(subscriptions)} subscriptions by user {user.username}")

        # Log audit action
        await log_admin_action(
            db=db,
            user_id=user.id,
            username=user.username,
            action="batch_delete",
            resource_type="subscription",
            details={"count": len(subscriptions), "ids": ids},
            request=request,
        )

        return Response(status_code=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Batch delete error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to batch delete subscriptions",
        )


# ==================== Audit Log Management ====================


@router.get("/audit-logs", response_class=HTMLResponse)
async def audit_logs_page(
    request: Request,
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
    page: int = 1,
    per_page: int = 50,
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
):
    """Display audit logs page with filtering and pagination."""
    try:
        # Build query
        query = select(AdminAuditLog).order_by(AdminAuditLog.created_at.desc())

        # Apply filters
        if action:
            query = query.where(AdminAuditLog.action == action)
        if resource_type:
            query = query.where(AdminAuditLog.resource_type == resource_type)

        # Get total count
        count_query = select(func.count()).select_from(AdminAuditLog)
        if action:
            count_query = count_query.where(AdminAuditLog.action == action)
        if resource_type:
            count_query = count_query.where(AdminAuditLog.resource_type == resource_type)

        total_result = await db.execute(count_query)
        total_count = total_result.scalar() or 0

        # Apply pagination
        offset = (page - 1) * per_page
        query = query.limit(per_page).offset(offset)

        # Execute query
        result = await db.execute(query)
        audit_logs = result.scalars().all()

        # Calculate pagination info
        total_pages = (total_count + per_page - 1) // per_page

        return templates.TemplateResponse(
            "audit_logs.html",
            {
                "request": request,
                "user": user,
                "audit_logs": audit_logs,
                "page": page,
                "per_page": per_page,
                "total_count": total_count,
                "total_pages": total_pages,
                "action_filter": action,
                "resource_type_filter": resource_type,
                "messages": [],
            },
        )
    except Exception as e:
        logger.error(f"Audit logs page error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to load audit logs",
        )


# ==================== User Management ====================


@router.get("/users", response_class=HTMLResponse)
async def users_page(
    request: Request,
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Display users management page."""
    try:
        # Get all users
        result = await db.execute(
            select(User).order_by(User.created_at.desc())
        )
        users = result.scalars().all()

        return templates.TemplateResponse(
            "users.html",
            {
                "request": request,
                "user": user,
                "users": users,
                "messages": [],
            },
        )
    except Exception as e:
        logger.error(f"Users page error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to load users",
        )


@router.put("/users/{user_id}/toggle")
async def toggle_user(
    user_id: int,
    request: Request,
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Toggle user active status."""
    try:
        result = await db.execute(
            select(User).where(User.id == user_id)
        )
        target_user = result.scalar_one_or_none()

        if not target_user:
            raise HTTPException(status_code=404, detail="User not found")

        # Prevent disabling self
        if target_user.id == user.id:
            raise HTTPException(status_code=400, detail="Cannot disable your own account")

        # Toggle status
        if target_user.status == UserStatus.ACTIVE:
            target_user.status = UserStatus.INACTIVE
        else:
            target_user.status = UserStatus.ACTIVE

        await db.commit()
        await db.refresh(target_user)

        logger.info(
            f"User {user_id} toggled to {target_user.status} by user {user.username}"
        )

        # Log audit action
        await log_admin_action(
            db=db,
            user_id=user.id,
            username=user.username,
            action="toggle",
            resource_type="user",
            resource_id=user_id,
            resource_name=target_user.username,
            details={"status": target_user.status},
            request=request,
        )

        # Return updated row HTML
        return templates.TemplateResponse(
            "users.html",
            {
                "request": request,
                "user": user,
                "users": [target_user],
                "messages": [],
            },
        )
    except Exception as e:
        logger.error(f"Toggle user error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to toggle user",
        )


@router.put("/users/{user_id}/reset-password")
async def reset_user_password(
    user_id: int,
    request: Request,
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Reset user password to a random value."""
    try:
        result = await db.execute(
            select(User).where(User.id == user_id)
        )
        target_user = result.scalar_one_or_none()

        if not target_user:
            raise HTTPException(status_code=404, detail="User not found")

        # Generate random password
        from app.core.security import get_password_hash
        new_password = secrets.token_urlsafe(16)
        target_user.hashed_password = get_password_hash(new_password)

        await db.commit()
        await db.refresh(target_user)

        logger.info(
            f"User {user_id} password reset by user {user.username}"
        )

        # Log audit action
        await log_admin_action(
            db=db,
            user_id=user.id,
            username=user.username,
            action="reset_password",
            resource_type="user",
            resource_id=user_id,
            resource_name=target_user.username,
            request=request,
        )

        # Return success message with new password
        return Response(
            content=f"Password reset successful. New password: {new_password}",
            status_code=status.HTTP_200_OK,
        )
    except Exception as e:
        logger.error(f"Reset password error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reset password",
        )


# ==================== System Monitoring ====================


@router.get("/monitoring", response_class=HTMLResponse)
async def monitoring_page(
    request: Request,
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Display system monitoring dashboard."""
    try:
        import psutil
        from datetime import datetime, timedelta

        # System resources
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        # Database statistics
        user_count_query = select(func.count()).select_from(User)
        user_count_result = await db.execute(user_count_query)
        user_count = user_count_result.scalar() or 0

        apikey_count_query = select(func.count()).select_from(AIModelConfig)
        apikey_count_result = await db.execute(apikey_count_query)
        apikey_count = apikey_count_result.scalar() or 0

        subscription_count_query = select(func.count()).select_from(Subscription)
        subscription_count_result = await db.execute(subscription_count_query)
        subscription_count = subscription_count_result.scalar() or 0

        # Active subscriptions
        active_subscription_query = select(func.count()).select_from(Subscription).where(Subscription.is_active == True)
        active_subscription_result = await db.execute(active_subscription_query)
        active_subscription_count = active_subscription_result.scalar() or 0

        # Recent audit logs (last 24 hours)
        yesterday = datetime.utcnow() - timedelta(days=1)
        recent_logs_query = select(func.count()).select_from(AdminAuditLog).where(AdminAuditLog.created_at >= yesterday)
        recent_logs_result = await db.execute(recent_logs_query)
        recent_logs_count = recent_logs_result.scalar() or 0

        # Failed operations (last 24 hours)
        failed_ops_query = select(func.count()).select_from(AdminAuditLog).where(
            AdminAuditLog.created_at >= yesterday,
            AdminAuditLog.status == "failed"
        )
        failed_ops_result = await db.execute(failed_ops_query)
        failed_ops_count = failed_ops_result.scalar() or 0

        # Recent audit logs for display
        recent_audit_logs_query = select(AdminAuditLog).order_by(AdminAuditLog.created_at.desc()).limit(10)
        recent_audit_logs_result = await db.execute(recent_audit_logs_query)
        recent_audit_logs = recent_audit_logs_result.scalars().all()

        return templates.TemplateResponse(
            "monitoring.html",
            {
                "request": request,
                "user": user,
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_used_gb": memory.used / (1024 ** 3),
                "memory_total_gb": memory.total / (1024 ** 3),
                "disk_percent": disk.percent,
                "disk_used_gb": disk.used / (1024 ** 3),
                "disk_total_gb": disk.total / (1024 ** 3),
                "user_count": user_count,
                "apikey_count": apikey_count,
                "subscription_count": subscription_count,
                "active_subscription_count": active_subscription_count,
                "recent_logs_count": recent_logs_count,
                "failed_ops_count": failed_ops_count,
                "recent_audit_logs": recent_audit_logs,
                "messages": [],
            },
        )
    except Exception as e:
        logger.error(f"Monitoring page error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to load monitoring dashboard",
        )





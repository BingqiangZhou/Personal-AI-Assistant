"""Admin panel routes."""
import logging
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Body, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import encrypt_data, decrypt_data

from app.admin.dependencies import admin_required, admin_required_no_2fa, create_admin_session
from app.admin.schemas import AdminLoginForm
from app.admin.csrf import generate_csrf_token, validate_csrf_token
from app.admin.audit import log_admin_action
from app.admin.models import AdminAuditLog, SystemSettings
from app.admin.twofa import generate_totp_secret, generate_qr_code, verify_totp_token
from app.admin.first_run import check_admin_exists
from app.admin.monitoring import get_monitor_service
from app.core.database import get_db_session
from app.core.security import verify_password, get_password_hash
from app.domains.ai.models import AIModelConfig, ModelType
from app.domains.subscription.models import Subscription, UpdateFrequency, SubscriptionStatus
from app.domains.user.models import User, UserStatus
from app.domains.user.repositories import UserRepository

logger = logging.getLogger(__name__)

router = APIRouter()

# Setup Jinja2 templates with custom functions
templates = Jinja2Templates(directory="app/admin/templates")
# Add min function to template globals
templates.env.globals["min"] = min

# Custom filter to convert UTC datetime to local timezone (Asia/Shanghai, UTC+8)
def to_local_timezone(dt: datetime, format_str: str = '%Y-%m-%d %H:%M:%S') -> str:
    """Convert UTC datetime to Asia/Shanghai timezone and format it."""
    if dt is None:
        return '-'
    # Ensure dt is timezone-aware (assume UTC if naive)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    # Convert to Asia/Shanghai timezone (UTC+8)
    from zoneinfo import ZoneInfo
    shanghai_tz = ZoneInfo('Asia/Shanghai')
    local_dt = dt.astimezone(shanghai_tz)
    return local_dt.strftime(format_str)

# Register the custom filter
templates.env.filters['to_local'] = to_local_timezone

# Custom filter for uptime formatting
def format_uptime(seconds: float) -> str:
    """Format uptime seconds to human readable string."""
    if seconds is None:
        return '-'
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    if days > 0:
        return f"{days}天 {hours}小时"
    elif hours > 0:
        return f"{hours}小时 {minutes}分钟"
    else:
        return f"{minutes}分钟"

# Custom filter for bytes formatting
def format_bytes(bytes_value: int) -> str:
    """Format bytes to human readable string."""
    if bytes_value is None:
        return '-'
    if bytes_value >= 1073741824:
        return f"{bytes_value / 1073741824:.1f} GB"
    elif bytes_value >= 1048576:
        return f"{bytes_value / 1048576:.1f} MB"
    elif bytes_value >= 1024:
        return f"{bytes_value / 1024:.1f} KB"
    else:
        return f"{bytes_value} B"

# Custom filter for number formatting
def format_number(value: int) -> str:
    """Format number with thousand separators."""
    if value is None:
        return '-'
    return f"{value:,}"

# Register custom filters
templates.env.filters['format_uptime'] = format_uptime
templates.env.filters['format_bytes'] = format_bytes
templates.env.filters['format_number'] = format_number

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
    model_type_filter: Optional[str] = None,
    page: int = 1,
    per_page: int = 10,
):
    """Display API keys management page with filtering and pagination."""
    try:
        # Build base query
        query = select(AIModelConfig)

        # Apply model type filter if specified
        if model_type_filter and model_type_filter in ['transcription', 'text_generation']:
            query = query.where(AIModelConfig.model_type == model_type_filter)

        # Get total count
        count_query = select(func.count()).select_from(query.subquery())
        total_count_result = await db.execute(count_query)
        total_count = total_count_result.scalar() or 0

        # Calculate pagination
        total_pages = (total_count + per_page - 1) // per_page if total_count > 0 else 1
        offset = (page - 1) * per_page

        # Get paginated results, ordered by priority then created_at
        result = await db.execute(
            query.order_by(AIModelConfig.priority.asc(), AIModelConfig.created_at.desc())
            .limit(per_page)
            .offset(offset)
        )
        apikeys = result.scalars().all()

        # Decrypt and mask API keys for display
        for config in apikeys:
            if config.api_key_encrypted and config.api_key:
                try:
                    decrypted_key = decrypt_data(config.api_key)
                    # Mask the API key: show first 4 and last 4 characters
                    if len(decrypted_key) > 8:
                        config.api_key = decrypted_key[:4] + '****' + decrypted_key[-4:]
                    else:
                        config.api_key = '****'
                except Exception as e:
                    logger.warning(f"Failed to decrypt API key for config {config.id}: {e}")
                    config.api_key = '****'

        return templates.TemplateResponse(
            "apikeys.html",
            {
                "request": request,
                "user": user,
                "apikeys": apikeys,
                "model_type_filter": model_type_filter or '',
                "page": page,
                "per_page": per_page,
                "total_count": total_count,
                "total_pages": total_pages,
                "messages": [],
            },
        )
    except Exception as e:
        logger.error(f"API keys page error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to load API keys",
        )


@router.post("/apikeys/test")
async def test_apikey(
    request: Request,
    api_url: str = Body(...),
    api_key: str = Body(...),
    model_type: str = Body(...),
    name: Optional[str] = Body(None),
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Test API key connection before creating a new model config."""
    try:
        # Import the AI service for validation
        from app.domains.ai.services import AIModelConfigService

        service = AIModelConfigService(db)

        # Convert model_type string to ModelType enum
        try:
            model_type_enum = ModelType(model_type)
        except ValueError:
            return JSONResponse(
                content={"success": False, "message": f"无效的模型类型: {model_type}"},
                status_code=status.HTTP_400_BAD_REQUEST
            )

        # Validate the API key
        validation_result = await service.validate_api_key(
            api_url=api_url,
            api_key=api_key,
            model_id=name,
            model_type=model_type_enum
        )

        if validation_result.valid:
            logger.info(f"API key test successful for model type {model_type} by user {user.username}")
            return JSONResponse(content={
                "success": True,
                "message": "API密钥测试成功",
                "test_result": validation_result.test_result,
                "response_time_ms": validation_result.response_time_ms
            })
        else:
            logger.warning(f"API key test failed for model type {model_type} by user {user.username}: {validation_result.error_message}")
            return JSONResponse(
                content={
                    "success": False,
                    "message": f"API密钥测试失败: {validation_result.error_message}",
                    "error_message": validation_result.error_message
                },
                status_code=status.HTTP_400_BAD_REQUEST
            )
    except Exception as e:
        logger.error(f"API key test error: {e}")
        return JSONResponse(
            content={"success": False, "message": f"测试失败: {str(e)}"},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@router.post("/apikeys/create")
async def create_apikey(
    request: Request,
    name: str = Form(...),
    display_name: str = Form(...),
    model_type: str = Form(...),
    api_url: str = Form(...),
    api_key: str = Form(...),
    provider: str = Form(default="custom"),
    description: Optional[str] = Form(None),
    priority: int = Form(default=1),
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Create a new AI Model Config with API key."""
    try:
        # Encrypt the API key using Fernet symmetric encryption
        encrypted_key = encrypt_data(api_key)

        # Create AI Model Config - use name as model_id
        new_config = AIModelConfig(
            name=name,
            display_name=display_name,
            description=description,
            model_type=model_type,
            api_url=api_url,
            api_key=encrypted_key,
            api_key_encrypted=True,
            model_id=name,  # Use name as model_id
            provider=provider,
            is_active=True,
            priority=priority,
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
                "priority": priority,
            },
            request=request,
        )

        # Return JSON response for AJAX handling
        return JSONResponse(content={
            "success": True,
            "message": f"模型配置 '{display_name}' 已成功创建"
        })
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

        return JSONResponse(content={"success": True})
    except Exception as e:
        logger.error(f"Toggle API key error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to toggle API key",
        )


@router.put("/apikeys/{key_id}/edit")
async def edit_apikey(
    key_id: int,
    request: Request,
    name: Optional[str] = Body(None),
    display_name: Optional[str] = Body(None),
    model_type: Optional[str] = Body(None),
    api_url: Optional[str] = Body(None),
    api_key: Optional[str] = Body(None),
    provider: Optional[str] = Body(None),
    description: Optional[str] = Body(None),
    priority: Optional[int] = Body(None),
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Edit an AI Model Config."""
    try:
        result = await db.execute(
            select(AIModelConfig).where(AIModelConfig.id == key_id)
        )
        model_config = result.scalar_one_or_none()

        if not model_config:
            raise HTTPException(status_code=404, detail="API key not found")

        # Store old values for audit log
        old_values = {
            "name": model_config.name,
            "display_name": model_config.display_name,
            "model_type": model_config.model_type,
            "api_url": model_config.api_url,
            "provider": model_config.provider,
            "description": model_config.description,
            "priority": model_config.priority,
        }

        # Update fields if provided
        if name is not None:
            model_config.name = name
            model_config.model_id = name  # Update model_id to match name
        if display_name is not None:
            model_config.display_name = display_name
        if model_type is not None:
            model_config.model_type = model_type
        if api_url is not None:
            model_config.api_url = api_url
        if provider is not None:
            model_config.provider = provider
        if description is not None:
            model_config.description = description
        if priority is not None:
            model_config.priority = priority
        if api_key is not None and api_key.strip():
            # Encrypt new API key
            encrypted_key = encrypt_data(api_key)
            model_config.api_key = encrypted_key
            model_config.api_key_encrypted = True

        await db.commit()
        await db.refresh(model_config)

        logger.info(f"AI Model Config {key_id} updated by user {user.username}")

        # Log audit action
        await log_admin_action(
            db=db,
            user_id=user.id,
            username=user.username,
            action="update",
            resource_type="apikey",
            resource_id=key_id,
            resource_name=model_config.display_name,
            details={"old_values": old_values, "new_values": {
                "name": model_config.name,
                "display_name": model_config.display_name,
                "model_type": model_config.model_type,
                "priority": model_config.priority,
            }},
            request=request,
        )

        return JSONResponse(content={"success": True})
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Edit API key error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update API key",
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

        return JSONResponse(content={"success": True})
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
    page: int = 1,
    per_page: int = 10,
):
    """Display RSS subscriptions management page with pagination."""
    try:
        # Get total count
        count_result = await db.execute(select(func.count()).select_from(Subscription))
        total_count = count_result.scalar() or 0

        # Calculate pagination
        total_pages = (total_count + per_page - 1) // per_page
        offset = (page - 1) * per_page

        # Get paginated subscriptions
        result = await db.execute(
            select(Subscription)
            .order_by(Subscription.created_at.desc())
            .limit(per_page)
            .offset(offset)
        )
        subscriptions = result.scalars().all()

        # Get default frequency settings from the first subscription (if any)
        # This is a simple approach - could be stored in a settings table instead
        default_frequency = UpdateFrequency.HOURLY.value
        default_update_time = "00:00"
        default_day_of_week = 1

        if total_count > 0:
            # Get most common frequency settings from existing subscriptions
            freq_result = await db.execute(
                select(Subscription.update_frequency, Subscription.update_time, Subscription.update_day_of_week)
                .where(Subscription.source_type == "rss")
                .group_by(Subscription.update_frequency, Subscription.update_time, Subscription.update_day_of_week)
                .order_by(func.count().desc())
                .limit(1)
            )
            row = freq_result.first()
            if row:
                default_frequency = row[0]
                default_update_time = row[1] or "00:00"
                default_day_of_week = row[2] or 1

        return templates.TemplateResponse(
            "subscriptions.html",
            {
                "request": request,
                "user": user,
                "subscriptions": subscriptions,
                "page": page,
                "per_page": per_page,
                "total_count": total_count,
                "total_pages": total_pages,
                "default_frequency": default_frequency,
                "default_update_time": default_update_time,
                "default_day_of_week": default_day_of_week,
                "messages": [],
            },
        )
    except Exception as e:
        logger.error(f"Subscriptions page error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to load subscriptions",
        )


@router.post("/subscriptions/update-frequency")
async def update_subscription_frequency(
    request: Request,
    update_frequency: str = Body(...),
    update_time: Optional[str] = Body(None),
    update_day: Optional[int] = Body(None),
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Update update frequency settings for all RSS subscriptions."""
    try:
        # Validate frequency
        if update_frequency not in [UpdateFrequency.HOURLY.value, UpdateFrequency.DAILY.value, UpdateFrequency.WEEKLY.value]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid update frequency"
            )

        # Validate time format for DAILY and WEEKLY
        if update_frequency in [UpdateFrequency.DAILY.value, UpdateFrequency.WEEKLY.value]:
            if not update_time:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Update time is required for DAILY and WEEKLY frequency"
                )
            try:
                hour, minute = map(int, update_time.split(':'))
                if not (0 <= hour <= 23 and 0 <= minute <= 59):
                    raise ValueError
            except (ValueError, AttributeError):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid time format. Use HH:MM"
                )

        # Validate day of week for WEEKLY
        day_of_week = None
        if update_frequency == UpdateFrequency.WEEKLY.value:
            if not update_day or not (1 <= update_day <= 7):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid day of week. Must be 1-7"
                )
            day_of_week = update_day

        # Update all RSS subscriptions
        stmt = select(Subscription).where(Subscription.source_type == "rss")
        result = await db.execute(stmt)
        subscriptions = result.scalars().all()

        update_count = 0
        for sub in subscriptions:
            sub.update_frequency = update_frequency
            if update_frequency in [UpdateFrequency.DAILY.value, UpdateFrequency.WEEKLY.value]:
                sub.update_time = update_time
            else:
                sub.update_time = None

            if update_frequency == UpdateFrequency.WEEKLY.value:
                sub.update_day_of_week = day_of_week
            else:
                sub.update_day_of_week = None
            update_count += 1

        await db.commit()

        logger.info(f"Updated frequency settings for {update_count} RSS subscriptions by user {user.username}")

        # Log audit action
        await log_admin_action(
            db=db,
            user_id=user.id,
            username=user.username,
            action="update",
            resource_type="subscription_frequency",
            resource_name=f"All RSS subscriptions ({update_count})",
            details={
                "update_frequency": update_frequency,
                "update_time": update_time,
                "update_day_of_week": day_of_week,
            },
            request=request,
        )

        return JSONResponse(content={
            "success": True,
            "message": f"已更新 {update_count} 个RSS订阅的更新频率设置"
        })
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Update subscription frequency error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update frequency settings",
        )


@router.put("/subscriptions/{sub_id}/edit")
async def edit_subscription(
    sub_id: int,
    request: Request,
    title: Optional[str] = Body(None),
    source_url: Optional[str] = Body(None),
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
        if source_url is not None:
            subscription.source_url = source_url

        await db.commit()
        await db.refresh(subscription)

        logger.info(f"Subscription {sub_id} edited by user {user.username}")

        # Log audit action
        await log_admin_action(
            db=db,
            user_id=user.id,
            username=user.username,
            action="update",
            resource_type="subscription",
            resource_id=sub_id,
            resource_name=subscription.title,
            details={"title": title, "source_url": source_url},
            request=request,
        )

        return JSONResponse(content={"success": True})
    except Exception as e:
        logger.error(f"Edit subscription error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to edit subscription",
        )


@router.post("/subscriptions/test-url")
async def test_subscription_url(
    request: Request,
    source_url: str = Body(..., embed=True),
    user: User = Depends(admin_required),
):
    """Test RSS feed URL before saving."""
    try:
        from app.core.feed_parser import FeedParser, FeedParserConfig, FeedParseOptions
        import time

        # Configure parser (same as backend subscription service)
        config = FeedParserConfig(
            max_entries=10000,  # 增加到10000以获取更真实的条目数
            strip_html=True,
            strict_mode=False,
            log_raw_feed=False
        )

        options = FeedParseOptions(
            strip_html_content=True,
            include_raw_metadata=False
        )

        # Test the RSS feed URL
        parser = FeedParser(config)
        start_time = time.time()

        try:
            result = await parser.parse_feed(source_url, options=options)
            response_time_ms = int((time.time() - start_time) * 1000)

            await parser.close()

            # Check for errors (use method call, not property)
            if not result.success or result.has_errors():
                error_messages = [err.message for err in result.errors] if result.errors else []
                return JSONResponse(
                    content={
                        "success": False,
                        "message": f"RSS feed test failed: {error_messages[0] if error_messages else 'Failed to parse feed'}",
                        "error_message": error_messages[0] if error_messages else "Failed to parse feed",
                    },
                    status_code=status.HTTP_400_BAD_REQUEST
                )

            logger.info(f"RSS feed test successful for {source_url} by user {user.username}")
            return JSONResponse(content={
                "success": True,
                "message": "RSS feed test successful",
                "feed_title": result.feed_info.title or "Untitled",
                "feed_description": result.feed_info.description or "",
                "entry_count": len(result.entries),
                "response_time_ms": response_time_ms
            })

        except Exception as e:
            await parser.close()
            raise e

    except Exception as e:
        logger.error(f"RSS feed test error: {e}")
        return JSONResponse(
            content={"success": False, "message": f"Test failed: {str(e)}"},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@router.delete("/subscriptions/{sub_id}/delete")
async def delete_subscription(
    sub_id: int,
    request: Request,
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Delete a subscription."""
    try:
        result = await db.execute(select(Subscription).where(Subscription.id == sub_id))
        subscription = result.scalar_one_or_none()

        if not subscription:
            raise HTTPException(status_code=404, detail="Subscription not found")

        # Store name before deletion
        resource_name = subscription.title

        await db.delete(subscription)
        await db.commit()

        logger.info(f"Subscription {sub_id} deleted by user {user.username}")

        # Log audit action
        await log_admin_action(
            db=db,
            user_id=user.id,
            username=user.username,
            action="delete",
            resource_type="subscription",
            resource_id=sub_id,
            resource_name=resource_name,
            request=request,
        )

        return JSONResponse(content={"success": True})
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

        # Log audit action
        await log_admin_action(
            db=db,
            user_id=user.id,
            username=user.username,
            action="update",
            resource_type="subscription",
            resource_id=sub_id,
            resource_name=subscription.title,
            details={"action": "refresh"},
            request=request,
        )

        return JSONResponse(content={"success": True})
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
    per_page: int = 10,
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
    page: int = 1,
    per_page: int = 10,
):
    """Display users management page with pagination."""
    try:
        # Get total count
        count_result = await db.execute(select(func.count()).select_from(User))
        total_count = count_result.scalar() or 0

        # Calculate pagination
        total_pages = (total_count + per_page - 1) // per_page
        offset = (page - 1) * per_page

        # Get paginated users
        result = await db.execute(
            select(User)
            .order_by(User.created_at.desc())
            .limit(per_page)
            .offset(offset)
        )
        users = result.scalars().all()

        return templates.TemplateResponse(
            "users.html",
            {
                "request": request,
                "user": user,
                "users": users,
                "page": page,
                "per_page": per_page,
                "total_count": total_count,
                "total_pages": total_pages,
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

        return JSONResponse(content={"success": True, "status": target_user.status})
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

        return JSONResponse(content={
            "success": True,
            "new_password": new_password,
            "message": f"Password reset successful. New password: {new_password}"
        })
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
        from datetime import timedelta

        # Get system metrics
        monitor = get_monitor_service()
        metrics = monitor.get_all_metrics()

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
        active_subscription_query = select(func.count()).select_from(Subscription).where(Subscription.status == SubscriptionStatus.ACTIVE)
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
                # Current time
                "current_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                # System info
                "hostname": metrics.system_info.hostname,
                "os_type": metrics.system_info.os_type,
                "os_version": metrics.system_info.os_version,
                "architecture": metrics.system_info.architecture,
                "uptime_seconds": metrics.system_info.uptime_seconds,
                "cpu_count": metrics.system_info.cpu_count,
                "current_users": metrics.system_info.current_users,
                # CPU metrics
                "cpu_percent": metrics.cpu.usage_percent,
                "per_cpu_percent": metrics.cpu.per_cpu_percent,
                "load_average_1min": metrics.cpu.load_average_1min,
                "load_average_5min": metrics.cpu.load_average_5min,
                "load_average_15min": metrics.cpu.load_average_15min,
                "context_switches": metrics.cpu.context_switches,
                "interrupts": metrics.cpu.interrupts,
                # Memory metrics
                "memory_percent": metrics.memory.percent,
                "memory_used_gb": metrics.memory.used_gb,
                "memory_total_gb": metrics.memory.total_gb,
                "memory_available_gb": metrics.memory.available_gb,
                "memory_buffered_gb": metrics.memory.buffered_gb,
                "memory_cached_gb": metrics.memory.cached_gb,
                "swap_percent": metrics.memory.swap_percent,
                "swap_used_gb": metrics.memory.swap_used_gb,
                "swap_total_gb": metrics.memory.swap_total_gb,
                # Disk metrics
                "disk_partitions": metrics.disk.partitions,
                # Network metrics
                "network_interfaces": metrics.network.interfaces,
                # Database stats
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


# ==================== Monitoring API Endpoints ====================


@router.get("/api/monitoring/all")
async def get_all_metrics_api(
    user: User = Depends(admin_required),
):
    """Get all system metrics as JSON."""
    try:
        monitor = get_monitor_service()
        metrics = monitor.get_all_metrics()
        return JSONResponse(content=metrics.model_dump())
    except Exception as e:
        logger.error(f"Get all metrics API error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get system metrics",
        )


@router.get("/api/monitoring/system-info")
async def get_system_info_api(
    user: User = Depends(admin_required),
):
    """Get system basic information as JSON."""
    try:
        monitor = get_monitor_service()
        info = monitor.get_system_info()
        return JSONResponse(content=info.model_dump())
    except Exception as e:
        logger.error(f"Get system info API error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get system info",
        )


@router.get("/api/monitoring/cpu")
async def get_cpu_metrics_api(
    user: User = Depends(admin_required),
):
    """Get CPU metrics as JSON."""
    try:
        monitor = get_monitor_service()
        metrics = monitor.get_cpu_metrics()
        return JSONResponse(content=metrics.model_dump())
    except Exception as e:
        logger.error(f"Get CPU metrics API error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get CPU metrics",
        )


@router.get("/api/monitoring/memory")
async def get_memory_metrics_api(
    user: User = Depends(admin_required),
):
    """Get memory metrics as JSON."""
    try:
        monitor = get_monitor_service()
        metrics = monitor.get_memory_metrics()
        return JSONResponse(content=metrics.model_dump())
    except Exception as e:
        logger.error(f"Get memory metrics API error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get memory metrics",
        )


@router.get("/api/monitoring/disk")
async def get_disk_metrics_api(
    user: User = Depends(admin_required),
):
    """Get disk metrics as JSON."""
    try:
        monitor = get_monitor_service()
        metrics = monitor.get_disk_metrics()
        return JSONResponse(content=metrics.model_dump())
    except Exception as e:
        logger.error(f"Get disk metrics API error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get disk metrics",
        )


@router.get("/api/monitoring/network")
async def get_network_metrics_api(
    user: User = Depends(admin_required),
):
    """Get network metrics as JSON."""
    try:
        monitor = get_monitor_service()
        metrics = monitor.get_network_metrics()
        return JSONResponse(content=metrics.model_dump())
    except Exception as e:
        logger.error(f"Get network metrics API error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get network metrics",
        )


# ==================== System Settings ====================


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(
    request: Request,
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Display system settings page."""
    try:
        return templates.TemplateResponse(
            "settings.html",
            {
                "request": request,
                "user": user,
                "messages": [],
            },
        )
    except Exception as e:
        logger.error(f"Settings page error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to load settings page",
        )


@router.get("/settings/api/audio")
async def get_audio_settings(
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Get audio processing settings as JSON."""
    try:
        # Get chunk size setting
        chunk_size_result = await db.execute(
            select(SystemSettings).where(SystemSettings.key == "audio.chunk_size_mb")
        )
        chunk_size_setting = chunk_size_result.scalar_one_or_none()

        # Get max threads setting
        threads_result = await db.execute(
            select(SystemSettings).where(SystemSettings.key == "audio.max_concurrent_threads")
        )
        threads_setting = threads_result.scalar_one_or_none()

        chunk_size_mb = 10  # Default
        max_concurrent_threads = 4  # Default

        if chunk_size_setting and chunk_size_setting.value:
            chunk_size_mb = chunk_size_setting.value.get("value", 10)

        if threads_setting and threads_setting.value:
            max_concurrent_threads = threads_setting.value.get("value", 4)

        return JSONResponse(content={
            "chunk_size_mb": chunk_size_mb,
            "max_concurrent_threads": max_concurrent_threads,
        })
    except Exception as e:
        logger.error(f"Get audio settings error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get audio settings",
        )


@router.post("/settings/api/audio")
async def update_audio_settings(
    request: Request,
    chunk_size_mb: int = Body(..., embed=True),
    max_concurrent_threads: int = Body(..., embed=True),
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Update audio processing settings."""
    try:
        # Validate chunk_size_mb range
        if not (5 <= chunk_size_mb <= 25):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="chunk_size_mb must be between 5 and 25"
            )

        # Validate max_concurrent_threads range
        if not (1 <= max_concurrent_threads <= 16):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="max_concurrent_threads must be between 1 and 16"
            )

        # Update chunk size setting
        chunk_size_result = await db.execute(
            select(SystemSettings).where(SystemSettings.key == "audio.chunk_size_mb")
        )
        chunk_size_setting = chunk_size_result.scalar_one_or_none()

        if chunk_size_setting:
            chunk_size_setting.value = {"value": chunk_size_mb, "min": 5, "max": 25}
        else:
            new_setting = SystemSettings(
                key="audio.chunk_size_mb",
                value={"value": chunk_size_mb, "min": 5, "max": 25},
                description="Audio chunk size in MB / 音频切块大小（MB）",
                category="audio"
            )
            db.add(new_setting)

        # Update max threads setting
        threads_result = await db.execute(
            select(SystemSettings).where(SystemSettings.key == "audio.max_concurrent_threads")
        )
        threads_setting = threads_result.scalar_one_or_none()

        if threads_setting:
            threads_setting.value = {"value": max_concurrent_threads, "min": 1, "max": 16}
        else:
            new_setting = SystemSettings(
                key="audio.max_concurrent_threads",
                value={"value": max_concurrent_threads, "min": 1, "max": 16},
                description="Maximum concurrent processing threads / 最大并发处理线程数",
                category="audio"
            )
            db.add(new_setting)

        await db.commit()

        logger.info(f"Audio settings updated by user {user.username}: chunk_size_mb={chunk_size_mb}, max_concurrent_threads={max_concurrent_threads}")

        # Log audit action
        await log_admin_action(
            db=db,
            user_id=user.id,
            username=user.username,
            action="update",
            resource_type="system_settings",
            resource_name="Audio processing settings",
            details={
                "chunk_size_mb": chunk_size_mb,
                "max_concurrent_threads": max_concurrent_threads,
            },
            request=request,
        )

        return JSONResponse(content={
            "success": True,
            "message": "设置已保存"
        })
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Update audio settings error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update audio settings",
        )





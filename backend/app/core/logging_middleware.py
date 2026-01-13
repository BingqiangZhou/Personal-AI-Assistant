"""
API 日志中间件

记录所有 API 请求和响应的详细信息
"""

import time
import logging
from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from urllib.parse import parse_qs
from itsdangerous import BadSignature, SignatureExpired

logger = logging.getLogger(__name__)


# 不需要记录日志的路径
SKIP_LOG_PATHS = {
    "/health",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/api/v1/openapi.json",
}


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    请求日志中间件

    记录:
    - 请求方法、路径、参数
    - 响应状态码
    - 请求处理时间
    - 客户端 IP
    """

    def __init__(self, app: ASGIApp, log_level: int = logging.INFO):
        super().__init__(app)
        self.log_level = log_level

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # 跳过健康检查和文档路径
        if request.url.path in SKIP_LOG_PATHS:
            return await call_next(request)

        # 记录开始时间
        start_time = time.time()

        # 获取请求信息
        method = request.method
        path = request.url.path
        query_params = str(request.url.query) if request.url.query else ""
        client_host = request.client.host if request.client else "unknown"

        # 获取用户 ID (如果已认证)
        user_id = "anonymous"
        try:
            # 方法1: 检查 JWT Bearer Token (API 认证)
            auth_header = request.headers.get("authorization", "")
            if auth_header and auth_header.startswith("Bearer "):
                # 提取 token
                token = auth_header.split(" ")[1]

                # 解析 JWT 获取用户信息
                from app.core.security import verify_token
                payload = verify_token(token)

                # 获取真实用户 ID (sub 字段)
                user_id = payload.get("sub", "authenticated")

            # 方法2: 检查 Admin Session Cookie (管理后台认证)
            elif "admin_session" in request.cookies:
                admin_session = request.cookies.get("admin_session")
                if admin_session:
                    from itsdangerous import URLSafeTimedSerializer
                    from app.core.config import settings

                    # 解析 session cookie
                    serializer = URLSafeTimedSerializer(settings.SECRET_KEY)
                    data = serializer.loads(
                        admin_session,
                        max_age=30 * 60  # 30分钟超时
                    )

                    # 获取用户 ID
                    user_id = f"admin_{data.get('user_id', 'unknown')}"

        except SignatureExpired:
            user_id = "admin_session_expired"
        except BadSignature:
            user_id = "admin_session_invalid"
        except Exception as e:
            # Token/Session 无效，保持 anonymous
            # 后续的路由守卫会处理认证问题
            pass

        # 记录请求开始
        logger.info(f"API请求开始: {method} {path} | 客户端: {client_host} | 用户: {user_id}")

        # 处理请求
        try:
            response = await call_next(request)

            # 计算处理时间
            process_time = time.time() - start_time

            # 记录响应
            status_code = response.status_code
            log_msg = (
                f"API请求完成: {method} {path} | "
                f"状态: {status_code} | "
                f"耗时: {process_time:.3f}s | "
                f"客户端: {client_host}"
            )

            # 根据状态码决定日志级别
            if status_code >= 500:
                logger.error(log_msg)
            elif status_code >= 400:
                logger.warning(log_msg)
            else:
                logger.info(log_msg)

            # 添加处理时间到响应头
            response.headers["X-Process-Time"] = f"{process_time:.3f}"

            return response

        except Exception as e:
            # 记录未处理的异常
            process_time = time.time() - start_time
            logger.error(
                f"API请求异常: {method} {path} | "
                f"错误: {str(e)} | "
                f"耗时: {process_time:.3f}s | "
                f"客户端: {client_host}",
                exc_info=True
            )
            raise


class SlowRequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    慢请求日志中间件

    记录处理时间超过阈值的请求
    """

    def __init__(self, app: ASGIApp, slow_threshold: float = 5.0):
        super().__init__(app)
        self.slow_threshold = slow_threshold

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # 跳过健康检查
        if request.url.path in SKIP_LOG_PATHS:
            return await call_next(request)

        start_time = time.time()

        response = await call_next(request)
        process_time = time.time() - start_time

        # 记录慢请求
        if process_time > self.slow_threshold:
            logger.warning(
                f"慢请求检测: {request.method} {request.url.path} | "
                f"耗时: {process_time:.3f}s (阈值: {self.slow_threshold}s)"
            )

        return response


def setup_logging_middleware(app, slow_threshold: float = 5.0) -> None:
    """
    为 FastAPI 应用设置日志中间件

    Args:
        app: FastAPI 应用实例
        slow_threshold: 慢请求阈值 (秒)
    """
    # 添加请求日志中间件
    app.add_middleware(RequestLoggingMiddleware)

    # 添加慢请求日志中间件
    app.add_middleware(SlowRequestLoggingMiddleware, slow_threshold=slow_threshold)

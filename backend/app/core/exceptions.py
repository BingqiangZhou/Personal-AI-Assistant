"""Custom exception handlers.

自定义异常处理器
"""

import logging
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.json_encoder import CustomJSONResponse


logger = logging.getLogger(__name__)


class BaseCustomException(Exception):
    """Base custom exception.

    基础自定义异常
    """

    def __init__(
        self,
        message: str,
        status_code: int = 500,
        error_code: str | None = None,
        details: dict[str, Any] | None = None
    ):
        self.message = message
        self.status_code = status_code
        self.error_code = error_code or self.__class__.__name__
        self.details = details or {}
        super().__init__(self.message)


class NotFoundError(BaseCustomException):
    """Resource not found exception.

    资源未找到异常
    """

    def __init__(
        self,
        message: str = "Resource not found",
        **kwargs
    ):
        super().__init__(message, 404, **kwargs)


class BadRequestError(BaseCustomException):
    """Bad request exception.

    错误请求异常
    """

    def __init__(
        self,
        message: str = "Bad request",
        **kwargs
    ):
        super().__init__(message, 400, **kwargs)


class UnauthorizedError(BaseCustomException):
    """Unauthorized exception.

    未授权异常
    """

    def __init__(
        self,
        message: str = "Unauthorized",
        **kwargs
    ):
        super().__init__(message, 401, **kwargs)


class ForbiddenError(BaseCustomException):
    """Forbidden exception.

    禁止访问异常
    """

    def __init__(
        self,
        message: str = "Forbidden",
        **kwargs
    ):
        super().__init__(message, 403, **kwargs)


class ConflictError(BaseCustomException):
    """Conflict exception.

    冲突异常
    """

    def __init__(
        self,
        message: str = "Resource already exists",
        **kwargs
    ):
        super().__init__(message, 409, "CONFLICT", **kwargs)


class ValidationError(BaseCustomException):
    """Validation exception.

    验证异常
    """

    def __init__(
        self,
        message: str = "Validation failed",
        **kwargs
    ):
        super().__init__(message, 400, "VALIDATION_ERROR", **kwargs)


class DatabaseError(BaseCustomException):
    """Database exception.

    数据库异常
    """

    def __init__(
        self,
        message: str = "Database error",
        **kwargs
    ):
        super().__init__(message, 500, "DATABASE_ERROR", **kwargs)


class ExternalServiceError(BaseCustomException):
    """External service error exception.

    外部服务错误异常
    """

    def __init__(
        self,
        message: str = "External service error",
        **kwargs
    ):
        super().__init__(message, 502, "EXTERNAL_SERVICE_ERROR", **kwargs)


class FileProcessingError(BaseCustomException):
    """File processing error exception.

    文件处理错误异常
    """

    def __init__(
        self,
        message: str = "File processing error",
        **kwargs
    ):
        super().__init__(message, 422, "FILE_PROCESSING_ERROR", **kwargs)


async def custom_exception_handler(request: Request, exc: BaseCustomException) -> CustomJSONResponse:
    """Handle custom exceptions.

    处理自定义异常
    """
    logger.error(
        f"自定义异常: {exc.__class__.__name__} | "
        f"路径: {request.url.path} | "
        f"方法: {request.method} | "
        f"消息: {exc.message} | "
        f"状态码: {exc.status_code}"
    )

    # Build response content
    content = {
        "detail": exc.message,
        "type": exc.error_code,
        "status_code": exc.status_code
    }

    # Add details if present
    if exc.details:
        content["details"] = exc.details

    return CustomJSONResponse(status_code=exc.status_code, content=content)


async def http_exception_handler(request: Request, exc: HTTPException | StarletteHTTPException) -> CustomJSONResponse:
    """Handle HTTP exceptions.

    处理 HTTP 异常
    """
    logger.error(
        f"HTTP异常: {exc.status_code} | "
        f"路径: {request.url.path} | "
        f"方法: {request.method} | "
        f"详情: {exc.detail}"
    )
    return CustomJSONResponse(
        status_code=exc.status_code,
        content={
            "detail": str(exc.detail),
            "type": "HTTPException",
            "status_code": exc.status_code
        }
    )


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> CustomJSONResponse:
    """Handle validation exceptions.

    处理验证异常
    """
    errors = []
    for error in exc.errors():
        errors.append({
            "field": " -> ".join(str(x) for x in error["loc"]),
            "message": error["msg"],
            "type": error["type"]
        })

    logger.error(
        f"请求验证失败: {request.url.path} | "
        f"方法: {request.method} | "
        f"错误字段: {len(errors)}个 | "
        f"错误详情: {errors}"
    )

    return CustomJSONResponse(
        status_code=422,
        content={
            "detail": "Validation failed",
            "type": "VALIDATION_ERROR",
            "errors": errors
        }
    )


async def general_exception_handler(request: Request, exc: Exception) -> CustomJSONResponse:
    """Handle general exceptions.

    处理通用异常
    """
    logger.error(
        f"未处理异常: {exc.__class__.__name__} | "
        f"路径: {request.url.path} | "
        f"方法: {request.method} | "
        f"消息: {str(exc)}",
        exc_info=True
    )

    return CustomJSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "type": "INTERNAL_SERVER_ERROR",
            "status_code": 500
        }
    )


def setup_exception_handlers(app: FastAPI) -> None:
    """Setup exception handlers for the FastAPI app.

    为 FastAPI 应用设置异常处理器
    """
    app.add_exception_handler(BaseCustomException, custom_exception_handler)
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, general_exception_handler)


# Convenience functions for raising common exceptions
# 抛出常见异常的便捷函数

def raise_not_found(resource_type: str = "Resource", resource_id: Any = None) -> None:
    """Raise a NotFoundError with standardized message.

    抛出标准化的 NotFoundError
    """
    if resource_id is not None:
        message = f"{resource_type} with ID '{resource_id}' not found"
    else:
        message = f"{resource_type} not found"

    raise NotFoundError(
        message=message,
        details={"resource_type": resource_type, "resource_id": str(resource_id) if resource_id is not None else None}
    )


def raise_conflict(resource_type: str = "Resource", field: str = "field", value: Any = None) -> None:
    """Raise a ConflictError with standardized message.

    抛出标准化的 ConflictError
    """
    if value is not None:
        message = f"{resource_type} with {field} '{value}' already exists"
    else:
        message = f"{resource_type} already exists"

    raise ConflictError(
        message=message,
        details={"resource_type": resource_type, "field": field, "value": str(value) if value is not None else None}
    )


def raise_validation(message: str, field: str | None = None) -> None:
    """Raise a ValidationError with standardized message.

    抛出标准化的 ValidationError
    """
    details = {}
    if field:
        details["field"] = field

    raise ValidationError(
        message=message,
        details=details
    )

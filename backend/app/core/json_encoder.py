"""自定义 JSON 编码器

处理 datetime 序列化，确保时间戳带有时区信息
"""

import json
from datetime import UTC, datetime
from json import JSONEncoder
from typing import Any

from fastapi.responses import JSONResponse


class CustomJSONResponse(JSONResponse):
    """自定义 JSON 响应类，使用自定义编码器处理 datetime"""

    # 显式声明 media_type 包含 charset=utf-8
    media_type = "application/json; charset=utf-8"

    def render(self, content: Any) -> bytes:
        return json.dumps(
            content,
            ensure_ascii=False,
            allow_nan=False,
            indent=None,
            separators=(",", ":"),
            cls=CustomJSONEncoder,
        ).encode("utf-8")


class CustomJSONEncoder(JSONEncoder):
    """自定义 JSON 编码器

    - datetime 对象序列化为带时区信息的 ISO 8601 格式
    - 其他类型使用默认编码
    """

    def default(self, obj: Any) -> Any:
        # 处理 datetime 对象
        if isinstance(obj, datetime):
            # 如果 datetime 是 naive（没有时区信息），假设它是 UTC
            if obj.tzinfo is None:
                # 添加 UTC 时区信息
                obj = obj.replace(tzinfo=UTC)
            # 序列化为 ISO 格式（会包含时区信息，如 +00:00）
            return obj.isoformat()

        # 调用父类处理其他类型
        return super().default(obj)

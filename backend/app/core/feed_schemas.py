"""Feed parser data schemas.

RSS/Atom feed 解析的数据模型定义。
"""

from datetime import datetime
from typing import List, Optional, Dict, Any, Set
from pydantic import BaseModel, Field, field_validator, ConfigDict
from enum import Enum


class ParseErrorCode(str, Enum):
    """Parse error codes / 解析错误代码"""
    NETWORK_ERROR = "network_error"
    PARSE_ERROR = "parse_error"
    INVALID_FORMAT = "invalid_format"
    ENCODING_ERROR = "encoding_error"
    MISSING_REQUIRED_FIELD = "missing_required_field"


class ParseError(BaseModel):
    """Parse error details / 解析错误详情"""
    code: ParseErrorCode
    message: str
    entry_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class FeedInfo(BaseModel):
    """Basic feed information / Feed 基本信息"""
    title: str = ""
    description: str = ""
    link: str = ""
    author: Optional[str] = None
    icon_url: Optional[str] = None
    updated_at: Optional[datetime] = None
    language: Optional[str] = None
    raw_metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("title", mode="before")
    @classmethod
    def validate_title(cls, v: Any) -> str:
        """Ensure title is never None / 确保标题不为空"""
        if v is None:
            return ""
        return str(v).strip() if v else ""


class FeedEntry(BaseModel):
    """Single feed entry / 单个 Feed 条目"""
    # Required fields
    id: str
    title: str

    # Content fields
    content: str = ""
    summary: Optional[str] = None

    # Metadata
    author: Optional[str] = None
    link: Optional[str] = None
    image_url: Optional[str] = None
    tags: List[str] = Field(default_factory=list)

    # Dates
    published_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    # Raw data for debugging
    raw_metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("id", mode="before")
    @classmethod
    def validate_id(cls, v: Any) -> str:
        """Generate fallback ID if missing / 如果缺少 ID 则生成备用 ID"""
        if v:
            return str(v)
        # Fallback to link or generate hash-based ID
        return ""

    @field_validator("title", mode="before")
    @classmethod
    def validate_title(cls, v: Any) -> str:
        """Ensure title has a value / 确保有标题"""
        if v:
            return str(v).strip()
        return "Untitled"

    @field_validator("content", mode="before")
    @classmethod
    def validate_content(cls, v: Any) -> str:
        """Normalize content to string / 将内容规范化为字符串"""
        if isinstance(v, str):
            return v
        if isinstance(v, list) and v:
            # Handle feedparser content list format
            return str(v[0].get("value", "")) if isinstance(v[0], dict) else str(v[0])
        return ""

    @field_validator("tags", mode="before")
    @classmethod
    def validate_tags(cls, v: Any) -> List[str]:
        """Normalize tags to list of strings / 将标签规范化为字符串列表"""
        if isinstance(v, list):
            return [str(tag.term) if hasattr(tag, "term") else str(tag) for tag in v]
        return []

    def get_unique_tags(self) -> Set[str]:
        """Get unique tags as set / 获取唯一标签集合"""
        return set(self.tags)


class FeedParseResult(BaseModel):
    """Complete feed parse result / Feed 解析结果"""
    # Feed metadata
    feed_info: FeedInfo
    entries: List[FeedEntry] = Field(default_factory=list)

    # Parse status
    success: bool = True
    errors: List[ParseError] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)

    # Statistics
    total_entries: int = 0
    parsed_entries: int = 0
    skipped_entries: int = 0

    # Raw feedparser result for debugging
    raw_feed: Optional[Dict[str, Any]] = None

    def add_error(self, code: ParseErrorCode, message: str, **kwargs) -> None:
        """Add an error / 添加错误"""
        error = ParseError(
            code=code,
            message=message,
            details=kwargs if kwargs else None
        )
        self.errors.append(error)
        if code in (ParseErrorCode.NETWORK_ERROR, ParseErrorCode.PARSE_ERROR):
            self.success = False

    def add_warning(self, message: str) -> None:
        """Add a warning / 添加警告"""
        self.warnings.append(message)

    def has_errors(self) -> bool:
        """Check if result has errors / 检查是否有错误"""
        return len(self.errors) > 0

    def has_warnings(self) -> bool:
        """Check if result has warnings / 检查是否有警告"""
        return len(self.warnings) > 0


class FeedParserConfig(BaseModel):
    """Feed parser configuration / Feed 解析器配置"""
    # Parsing limits
    max_entries: int = 100
    max_content_length: int = 100000  # 100KB max content size

    # Content processing
    strip_html: bool = True
    validate_urls: bool = True

    # Error handling
    strict_mode: bool = False  # If True, fail on any entry error
    log_raw_feed: bool = False  # For debugging

    # HTTP settings
    timeout: float = 30.0
    user_agent: str = "Mozilla/5.0 (compatible; PersonalAIAssistant/1.0; +https://github.com/personal-ai-assistant)"

    model_config = ConfigDict(frozen=True)  # Immutable configuration


class FeedParseOptions(BaseModel):
    """Options for a single parse operation / 单次解析选项"""
    max_entries: Optional[int] = None  # Override default max_entries
    fields: Optional[List[str]] = None  # Specific fields to extract (None = all)

    # Content options
    include_raw_metadata: bool = False
    strip_html_content: bool = True

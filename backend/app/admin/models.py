"""Admin domain models."""

from datetime import datetime

from sqlalchemy import JSON, Column, DateTime, Index, Integer, String, Text

from app.core.database import Base


class AdminAuditLog(Base):
    """Admin operation audit log model."""

    __tablename__ = "admin_audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    username = Column(String(100), nullable=False)
    action = Column(String(100), nullable=False, index=True)  # create, update, delete, toggle, etc.
    resource_type = Column(String(50), nullable=False, index=True)  # apikey, subscription, user, etc.
    resource_id = Column(Integer, nullable=True)
    resource_name = Column(String(255), nullable=True)
    details = Column(JSON, nullable=True)  # Additional details about the operation
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    status = Column(String(20), nullable=False, default="success")  # success, failed
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    # Indexes for efficient querying
    __table_args__ = (
        Index('idx_user_action', 'user_id', 'action'),
        Index('idx_resource', 'resource_type', 'resource_id'),
        Index('idx_created_at_desc', 'created_at'),
    )


class SystemSettings(Base):
    """System settings model for storing configuration values."""
    __tablename__ = "system_settings"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, nullable=False, index=True, comment="Setting key")
    value = Column(JSON, nullable=True, comment="Setting value (JSON)")
    description = Column(String(500), nullable=True, comment="Setting description")
    category = Column(String(50), nullable=False, default="general", comment="Setting category: general, audio, ai, etc.")

    created_at = Column(DateTime, default=datetime.utcnow, comment="Created at")
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, comment="Updated at")

    def __repr__(self):
        return f"<SystemSettings(id={self.id}, key={self.key})>"

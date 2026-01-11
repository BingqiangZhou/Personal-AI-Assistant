"""Admin domain models."""

from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, Index
from datetime import datetime

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

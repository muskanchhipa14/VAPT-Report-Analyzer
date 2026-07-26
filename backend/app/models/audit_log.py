from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime

from app.core.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)

    user_name = Column(String, nullable=False)

    action = Column(String, nullable=False)

    module = Column(String, nullable=False)

    status = Column(String, nullable=False)

    timestamp = Column(DateTime, default=datetime.utcnow)
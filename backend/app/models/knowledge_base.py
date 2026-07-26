from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.sql import func

from app.core.database import Base


class KnowledgeBase(Base):
    __tablename__ = "knowledge_base"

    id = Column(Integer, primary_key=True, index=True)
    cwe_id = Column(String(50), nullable=False)
    vulnerability_name = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False)
    description = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    references = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
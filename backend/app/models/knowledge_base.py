from sqlalchemy import Column, Integer, String, Text
from app.core.database import Base


class KnowledgeBase(Base):
    __tablename__ = "knowledge_base"

    id = Column(Integer, primary_key=True, index=True)

    vulnerability_name = Column(String, nullable=False)

    cwe_id = Column(String, nullable=False)

    severity = Column(String, nullable=False)

    description = Column(Text, nullable=False)

    remediation = Column(Text, nullable=False)
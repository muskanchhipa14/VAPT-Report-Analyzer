from sqlalchemy import Column, Integer, String, Text
from app.core.database import Base

class KnowledgeBaseItem(Base):
    __tablename__ = "knowledge_base"

    id = Column(Integer, primary_key=True, index=True)
    cwe_id = Column(String, unique=True, index=True, nullable=False)
    vulnerability_name = Column(String, nullable=False)
    owasp_category = Column(String, nullable=False)
    capec_id = Column(String, nullable=True)
    description = Column(Text, nullable=False)
    recommendations = Column(Text, nullable=False)

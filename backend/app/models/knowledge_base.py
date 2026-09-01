from sqlalchemy import Column, Integer, String, Text
from app.core.database import Base

class KnowledgeBaseItem(Base):
    __tablename__ = "knowledge_base"

    id = Column(Integer, primary_key=True, index=True)
    cwe_id = Column(String, unique=True, index=True, nullable=False)
    vulnerability_name = Column(String, nullable=False)
    severity = Column(String, nullable=True, default="Medium")
    owasp_category = Column(String, nullable=True, default="General Security")
    capec_id = Column(String, nullable=True, default="N/A")
    description = Column(Text, nullable=False)
    recommendations = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)


# Alias for compatibility with backendnew references
KnowledgeBase = KnowledgeBaseItem

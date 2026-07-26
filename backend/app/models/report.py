from sqlalchemy import Column, Integer, String
from app.core.database import Base

class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    status = Column(String, default="Uploaded")
    vulnerabilities_count = Column(Integer, default=0)
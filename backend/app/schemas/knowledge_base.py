from pydantic import BaseModel
from typing import Optional


class KnowledgeBaseBase(BaseModel):
    cwe_id: str
    vulnerability_name: str
    severity: str
    description: str
    remediation: str
    references: Optional[str] = None


class KnowledgeBaseCreate(KnowledgeBaseBase):
    pass


class KnowledgeBaseUpdate(BaseModel):
    cwe_id: str | None = None
    vulnerability_name: str | None = None
    severity: str | None = None
    description: str | None = None
    remediation: str | None = None
    references: str | None = None


class KnowledgeBaseResponse(KnowledgeBaseBase):
    id: int

    class Config:
        from_attributes = True
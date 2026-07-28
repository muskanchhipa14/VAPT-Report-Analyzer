from pydantic import BaseModel


class KnowledgeBaseCreate(BaseModel):
    vulnerability_name: str
    cwe_id: str
    severity: str
    description: str
    remediation: str


class KnowledgeBaseUpdate(BaseModel):
    vulnerability_name: str
    cwe_id: str
    severity: str
    description: str
    remediation: str


class KnowledgeBaseResponse(BaseModel):
    id: int
    vulnerability_name: str
    cwe_id: str
    severity: str
    description: str
    remediation: str

    class Config:
        from_attributes = True
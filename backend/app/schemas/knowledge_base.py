from pydantic import BaseModel

class KnowledgeBaseItemBase(BaseModel):
    cwe_id: str
    vulnerability_name: str
    severity: str | None = "Medium"
    owasp_category: str | None = "General Security"
    capec_id: str | None = None
    description: str
    recommendations: str | None = None
    remediation: str | None = None

class KnowledgeBaseItemCreate(KnowledgeBaseItemBase):
    pass

class KnowledgeBaseItemResponse(KnowledgeBaseItemBase):
    id: int

    class Config:
        from_attributes = True

# Alias KnowledgeBaseResponse for backendnew compatibility
KnowledgeBaseResponse = KnowledgeBaseItemResponse


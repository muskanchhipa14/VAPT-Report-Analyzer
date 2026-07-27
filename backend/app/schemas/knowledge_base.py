from pydantic import BaseModel

class KnowledgeBaseItemBase(BaseModel):
    cwe_id: str
    vulnerability_name: str
    owasp_category: str
    capec_id: str | None = None
    description: str
    recommendations: str

class KnowledgeBaseItemCreate(KnowledgeBaseItemBase):
    pass

class KnowledgeBaseItemResponse(KnowledgeBaseItemBase):
    id: int

    class Config:
        from_attributes = True

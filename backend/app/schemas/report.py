from pydantic import BaseModel

class ReportCreate(BaseModel):
    filename: str


class ReportUpdate(BaseModel):
    status: str


class ReportResponse(BaseModel):
    id: int
    filename: str
    status: str
    vulnerabilities_count: int

    class Config:
        from_attributes = True
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
    user_id: int | None = None

    class Config:
        from_attributes = True
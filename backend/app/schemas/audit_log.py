from pydantic import BaseModel
from datetime import datetime


class AuditLogCreate(BaseModel):
    user_name: str
    action: str
    module: str
    status: str


class AuditLogUpdate(BaseModel):
    status: str


class AuditLogResponse(BaseModel):
    id: int
    user_name: str
    action: str
    module: str
    status: str
    timestamp: datetime

    class Config:
        from_attributes = True
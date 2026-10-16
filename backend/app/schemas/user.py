from typing import Optional
from pydantic import BaseModel, EmailStr
from app.core.roles import get_role_label, has_source_code_access, normalize_role


class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: Optional[str] = "user"


class UserUpdate(BaseModel):
    name: Optional[str] = None
    password: Optional[str] = None
    role: Optional[str] = None


class UserResponse(BaseModel):
    id: int
    name: str
    email: EmailStr
    role: str
    role_label: Optional[str] = None
    can_access_source_code: Optional[bool] = None

    def model_post_init(self, __context):
        if self.role_label is None:
            self.role_label = get_role_label(self.role)
        if self.can_access_source_code is None:
            self.can_access_source_code = has_source_code_access(self.role)

    class Config:
        from_attributes = True
from pydantic import BaseModel, EmailStr
from app.schemas.user import UserResponse

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class ChangePasswordRequest(BaseModel):
    email: EmailStr
    old_password: str
    new_password: str

class AuthResponse(BaseModel):
    message: str
    access_token: str | None = None
    token_type: str | None = None
    user: UserResponse | None = None
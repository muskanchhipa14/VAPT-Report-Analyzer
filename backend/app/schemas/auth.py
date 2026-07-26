from pydantic import BaseModel, EmailStr


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ChangePasswordRequest(BaseModel):
    email: EmailStr
    old_password: str
    new_password: str


class AuthResponse(BaseModel):
    message: str
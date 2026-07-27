from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.auth import (
    LoginRequest,
    ChangePasswordRequest,
    AuthResponse
)
from app.services import auth_service
from app.services.audit_helper import log_event
from app.core.security import create_access_token

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)


@router.post("/login", response_model=AuthResponse)
def login(
    credentials: LoginRequest,
    db: Session = Depends(get_db)
):

    user = auth_service.login(
        db,
        credentials.email,
        credentials.password
    )

    if not user:
        log_event(
            db,
            credentials.email,
            "Login",
            "Authentication",
            "Failed"
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    log_event(
        db,
        user.name,
        "Login",
        "Authentication",
        "Success"
    )

    # Generate JWT access token
    access_token = create_access_token(data={"sub": user.email, "role": user.role})

    return {
        "message": "Login Successful",
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role
        }
    }


@router.put("/change-password", response_model=AuthResponse)
def change_password(
    request: ChangePasswordRequest,
    db: Session = Depends(get_db)
):

    user = auth_service.change_password(
        db,
        request.email,
        request.old_password,
        request.new_password
    )

    if not user:
        log_event(
            db,
            request.email,
            "Change Password",
            "Authentication",
            "Failed"
        )

        raise HTTPException(
            status_code=400,
            detail="Invalid email or old password"
        )

    log_event(
        db,
        user.name,
        "Change Password",
        "Authentication",
        "Success"
    )

    # Generate new JWT access token
    access_token = create_access_token(data={"sub": user.email, "role": user.role})

    return {
        "message": "Password Updated Successfully",
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role
        }
    }


@router.post("/logout", response_model=AuthResponse)
def logout(
    db: Session = Depends(get_db)
):

    log_event(
        db,
        "System",
        "Logout",
        "Authentication",
        "Success"
    )

    return {
        "message": "Logout Successful"
    }
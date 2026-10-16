from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.user import UserCreate, UserUpdate, UserResponse
from app.services import user_service
from app.services.audit_helper import log_event

router = APIRouter(
    prefix="/users",
    tags=["Users"]
)


from app.core.security import get_current_user
from app.models.user import User


@router.get("/me")
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    from app.core.roles import get_role_label, has_source_code_access
    return {
        "id": current_user.id,
        "name": current_user.name,
        "email": current_user.email,
        "role": current_user.role,
        "role_label": get_role_label(current_user.role),
        "can_access_source_code": has_source_code_access(current_user.role)
    }


@router.post("/", response_model=UserResponse)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    # Check if email already exists
    existing_user = user_service.get_user_by_email(db, user.email)

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    new_user = user_service.create_user(
        db,
        user.name,
        user.email,
        user.password,
        role=user.role or "user"
    )

    log_event(
        db,
        new_user.name,
        f"Create User ({new_user.role})",
        "User Management",
        "Success"
    )

    return new_user


@router.get("/", response_model=list[UserResponse])
def get_users(db: Session = Depends(get_db)):
    users = user_service.get_users(db)

    log_event(
        db,
        "System",
        "View All Users",
        "User Management",
        "Success"
    )

    return users


@router.get("/{user_id}", response_model=UserResponse)
def get_user(user_id: int, db: Session = Depends(get_db)):
    user = user_service.get_user(db, user_id)

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    log_event(
        db,
        user.name,
        "View User",
        "User Management",
        "Success"
    )

    return user


@router.put("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    user: UserUpdate,
    db: Session = Depends(get_db)
):
    updated_user = user_service.update_user(
        db,
        user_id,
        user.name,
        user.password
    )

    if not updated_user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    log_event(
        db,
        updated_user.name,
        "Update User",
        "User Management",
        "Success"
    )

    return updated_user


@router.delete("/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db)):
    deleted_user = user_service.delete_user(db, user_id)

    if not deleted_user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    log_event(
        db,
        deleted_user.name,
        "Delete User",
        "User Management",
        "Success"
    )

    return {
        "status": "success",
        "message": f"User {user_id} deleted successfully."
    }
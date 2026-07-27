from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db

from app.schemas.audit_log import (
    AuditLogCreate,
    AuditLogUpdate,
    AuditLogResponse
)

from app.services import audit_log_service
from app.core.security import get_current_user
from app.models.audit_log import AuditLog

router = APIRouter(
    prefix="/logs",
    tags=["Audit Logs"]
)


@router.post("/", response_model=AuditLogResponse)
def create_log(
    log: AuditLogCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    # Verify user name matches
    if log.user_name != current_user.name:
        raise HTTPException(status_code=403, detail="Not authorized to log for another user")
    return audit_log_service.create_log(db, log)


@router.get("/", response_model=list[AuditLogResponse])
def get_logs(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    # Filter audit logs belonging to the current user
    return db.query(AuditLog).filter(AuditLog.user_name == current_user.name).all()


@router.get("/{log_id}", response_model=AuditLogResponse)
def get_log(
    log_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    log = audit_log_service.get_log(db, log_id)

    if not log:
        raise HTTPException(
            status_code=404,
            detail="Log not found"
        )

    if log.user_name != current_user.name:
        raise HTTPException(
            status_code=403,
            detail="Not authorized to access this log"
        )

    return log


@router.put("/{log_id}", response_model=AuditLogResponse)
def update_log(
    log_id: int,
    log: AuditLogUpdate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    db_log = audit_log_service.get_log(db, log_id)
    if not db_log:
        raise HTTPException(status_code=404, detail="Log not found")

    if db_log.user_name != current_user.name:
        raise HTTPException(status_code=403, detail="Not authorized to update this log")

    updated = audit_log_service.update_log(
        db,
        log_id,
        log.status
    )

    return updated


@router.delete("/{log_id}")
def delete_log(
    log_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    db_log = audit_log_service.get_log(db, log_id)
    if not db_log:
        raise HTTPException(status_code=404, detail="Log not found")

    if db_log.user_name != current_user.name:
        raise HTTPException(status_code=403, detail="Not authorized to delete this log")

    deleted = audit_log_service.delete_log(
        db,
        log_id
    )

    return {
        "status": "success",
        "message": "Log deleted successfully."
    }
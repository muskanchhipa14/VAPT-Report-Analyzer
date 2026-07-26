from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db

from app.schemas.audit_log import (
    AuditLogCreate,
    AuditLogUpdate,
    AuditLogResponse
)

from app.services import audit_log_service

router = APIRouter(
    prefix="/logs",
    tags=["Audit Logs"]
)


@router.post("/", response_model=AuditLogResponse)
def create_log(
    log: AuditLogCreate,
    db: Session = Depends(get_db)
):
    return audit_log_service.create_log(db, log)


@router.get("/", response_model=list[AuditLogResponse])
def get_logs(
    db: Session = Depends(get_db)
):
    return audit_log_service.get_logs(db)


@router.get("/{log_id}", response_model=AuditLogResponse)
def get_log(
    log_id: int,
    db: Session = Depends(get_db)
):

    log = audit_log_service.get_log(db, log_id)

    if not log:
        raise HTTPException(
            status_code=404,
            detail="Log not found"
        )

    return log


@router.put("/{log_id}", response_model=AuditLogResponse)
def update_log(
    log_id: int,
    log: AuditLogUpdate,
    db: Session = Depends(get_db)
):

    updated = audit_log_service.update_log(
        db,
        log_id,
        log.status
    )

    if not updated:
        raise HTTPException(
            status_code=404,
            detail="Log not found"
        )

    return updated


@router.delete("/{log_id}")
def delete_log(
    log_id: int,
    db: Session = Depends(get_db)
):

    deleted = audit_log_service.delete_log(
        db,
        log_id
    )

    if not deleted:
        raise HTTPException(
            status_code=404,
            detail="Log not found"
        )

    return {
        "status": "success",
        "message": "Log deleted successfully."
    }
from sqlalchemy.orm import Session

from app.schemas.audit_log import AuditLogCreate
from app.services import audit_log_service


def log_event(db: Session, user_name: str, action: str, module: str, status: str):
    log = AuditLogCreate(
        user_name=user_name,
        action=action,
        module=module,
        status=status
    )

    audit_log_service.create_log(db, log)
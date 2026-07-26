from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog


def create_log(db: Session, log):
    new_log = AuditLog(**log.model_dump())

    db.add(new_log)
    db.commit()
    db.refresh(new_log)

    return new_log


def get_logs(db: Session):
    return db.query(AuditLog).all()


def get_log(db: Session, log_id: int):
    return db.query(AuditLog).filter(
        AuditLog.id == log_id
    ).first()


def update_log(db: Session, log_id: int, status: str):

    log = get_log(db, log_id)

    if not log:
        return None

    log.status = status

    db.commit()
    db.refresh(log)

    return log


def delete_log(db: Session, log_id: int):

    log = get_log(db, log_id)

    if not log:
        return None

    db.delete(log)
    db.commit()

    return log
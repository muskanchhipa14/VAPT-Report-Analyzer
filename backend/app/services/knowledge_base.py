from sqlalchemy.orm import Session
from app.models.knowledge_base import KnowledgeBase


def create_entry(
    db: Session,
    vulnerability_name: str,
    cwe_id: str,
    severity: str,
    description: str,
    remediation: str
):
    entry = KnowledgeBase(
        vulnerability_name=vulnerability_name,
        cwe_id=cwe_id,
        severity=severity,
        description=description,
        remediation=remediation
    )

    db.add(entry)
    db.commit()
    db.refresh(entry)

    return entry


def get_entries(db: Session):
    return db.query(KnowledgeBase).all()


def get_entry(db: Session, entry_id: int):
    return db.query(KnowledgeBase).filter(
        KnowledgeBase.id == entry_id
    ).first()


def update_entry(
    db: Session,
    entry_id: int,
    vulnerability_name: str,
    cwe_id: str,
    severity: str,
    description: str,
    remediation: str
):
    entry = get_entry(db, entry_id)

    if entry:
        entry.vulnerability_name = vulnerability_name
        entry.cwe_id = cwe_id
        entry.severity = severity
        entry.description = description
        entry.remediation = remediation

        db.commit()
        db.refresh(entry)

    return entry


def delete_entry(db: Session, entry_id: int):
    entry = get_entry(db, entry_id)

    if entry:
        db.delete(entry)
        db.commit()

    return entry
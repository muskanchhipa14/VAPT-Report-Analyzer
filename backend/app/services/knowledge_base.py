from sqlalchemy.orm import Session
from app.models.knowledge_base import KnowledgeBase
from app.schemas.knowledge_base import (
    KnowledgeBaseCreate,
    KnowledgeBaseUpdate,
)


from fastapi import HTTPException
from sqlalchemy import or_


def create_vulnerability(db: Session, data: KnowledgeBaseCreate):

    existing = (
        db.query(KnowledgeBase)
        .filter(KnowledgeBase.cwe_id == data.cwe_id)
        .first()
    )

    if existing:
        raise HTTPException(
            status_code=400,
            detail="Vulnerability already exists."
        )

    vulnerability = KnowledgeBase(**data.model_dump())

    db.add(vulnerability)
    db.commit()
    db.refresh(vulnerability)

    return vulnerability


def get_all_vulnerabilities(db: Session):
    return db.query(KnowledgeBase).all()


def get_vulnerability(db: Session, vulnerability_id: int):
    return (
        db.query(KnowledgeBase)
        .filter(KnowledgeBase.id == vulnerability_id)
        .first()
    )


def update_vulnerability(
    db: Session,
    vulnerability_id: int,
    data: KnowledgeBaseUpdate,
):
    vulnerability = get_vulnerability(db, vulnerability_id)

    if not vulnerability:
        return None

    for key, value in data.model_dump(exclude_unset=True).items():
        setattr(vulnerability, key, value)

    db.commit()
    db.refresh(vulnerability)

    return vulnerability


def delete_vulnerability(db: Session, vulnerability_id: int):
    vulnerability = get_vulnerability(db, vulnerability_id)

    if not vulnerability:
        return None

    db.delete(vulnerability)
    db.commit()

    return vulnerability



def search_vulnerabilities(
    db: Session,
    cwe: str = None,
    severity: str = None,
    name: str = None,
):
    query = db.query(KnowledgeBase)

    if cwe:
        query = query.filter(KnowledgeBase.cwe_id.ilike(f"%{cwe}%"))

    if severity:
        query = query.filter(
            KnowledgeBase.severity.ilike(f"%{severity}%")
        )

    if name:
        query = query.filter(
            KnowledgeBase.vulnerability_name.ilike(f"%{name}%")
        )

    return query.all()
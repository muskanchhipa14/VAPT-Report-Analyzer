from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.knowledge_base import (
    KnowledgeBaseCreate,
    KnowledgeBaseUpdate,
    KnowledgeBaseResponse,
)
from app.services import knowledge_base

router = APIRouter(prefix="/knowledgebase", tags=["Knowledge Base"])


@router.post("/", response_model=KnowledgeBaseResponse)
def create(
    data: KnowledgeBaseCreate,
    db: Session = Depends(get_db),
):
    return knowledge_base.create_vulnerability(db, data)


@router.get("/", response_model=list[KnowledgeBaseResponse])
def get_all(db: Session = Depends(get_db)):
    return knowledge_base.get_all_vulnerabilities(db)


@router.get("/{vulnerability_id}", response_model=KnowledgeBaseResponse)
def get_one(
    vulnerability_id: int,
    db: Session = Depends(get_db),
):
    vulnerability = knowledge_base.get_vulnerability(
        db,
        vulnerability_id,
    )

    if not vulnerability:
        raise HTTPException(status_code=404, detail="Not found")

    return vulnerability


@router.put("/{vulnerability_id}", response_model=KnowledgeBaseResponse)
def update(
    vulnerability_id: int,
    data: KnowledgeBaseUpdate,
    db: Session = Depends(get_db),
):
    vulnerability = knowledge_base.update_vulnerability(
        db,
        vulnerability_id,
        data,
    )

    if not vulnerability:
        raise HTTPException(status_code=404, detail="Not found")

    return vulnerability


@router.delete("/{vulnerability_id}")
def delete(
    vulnerability_id: int,
    db: Session = Depends(get_db),
):
    vulnerability = knowledge_base.delete_vulnerability(
        db,
        vulnerability_id,
    )

    if not vulnerability:
        raise HTTPException(status_code=404, detail="Not found")

    return {"message": "Deleted successfully"}
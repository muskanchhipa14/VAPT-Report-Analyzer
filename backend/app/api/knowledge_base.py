from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db

from app.schemas.knowledge_base import (
    KnowledgeBaseCreate,
    KnowledgeBaseUpdate,
    KnowledgeBaseResponse
)

from app.services import knowledge_base

router = APIRouter(
    prefix="/knowledge-base",
    tags=["Knowledge Base"]
)


@router.post("/", response_model=KnowledgeBaseResponse)
def create_entry(
    item: KnowledgeBaseCreate,
    db: Session = Depends(get_db)
):
    return knowledge_base.create_entry(
        db,
        item.vulnerability_name,
        item.cwe_id,
        item.severity,
        item.description,
        item.remediation
    )


@router.get("/", response_model=list[KnowledgeBaseResponse])
def get_entries(
    db: Session = Depends(get_db)
):
    return knowledge_base.get_entries(db)


@router.get("/{entry_id}", response_model=KnowledgeBaseResponse)
def get_entry(
    entry_id: int,
    db: Session = Depends(get_db)
):
    entry = knowledge_base.get_entry(db, entry_id)

    if not entry:
        raise HTTPException(
            status_code=404,
            detail="Entry not found"
        )

    return entry


@router.put("/{entry_id}", response_model=KnowledgeBaseResponse)
def update_entry(
    entry_id: int,
    item: KnowledgeBaseUpdate,
    db: Session = Depends(get_db)
):
    entry = knowledge_base.update_entry(
        db,
        entry_id,
        item.vulnerability_name,
        item.cwe_id,
        item.severity,
        item.description,
        item.remediation
    )

    if not entry:
        raise HTTPException(
            status_code=404,
            detail="Entry not found"
        )

    return entry


@router.delete("/{entry_id}")
def delete_entry(
    entry_id: int,
    db: Session = Depends(get_db)
):
    entry = knowledge_base.delete_entry(
        db,
        entry_id
    )

    if not entry:
        raise HTTPException(
            status_code=404,
            detail="Entry not found"
        )

    return {
        "message": "Knowledge Base entry deleted successfully"
    }
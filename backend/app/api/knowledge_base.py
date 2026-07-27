from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.schemas.knowledge_base import KnowledgeBaseItemResponse
from app.services import knowledge_base as kb_service

router = APIRouter(
    prefix="/knowledge-base",
    tags=["Knowledge Base"]
)

@router.get("/", response_model=list[KnowledgeBaseItemResponse])
def get_knowledge_base_items(db: Session = Depends(get_db)):
    return kb_service.get_all_items(db)

@router.get("/{cwe_id}", response_model=KnowledgeBaseItemResponse)
def get_knowledge_base_item(cwe_id: str, db: Session = Depends(get_db)):
    item = kb_service.get_item_by_cwe(db, cwe_id)
    if not item:
        raise HTTPException(
            status_code=404,
            detail=f"Knowledge base item for {cwe_id} not found."
        )
    return item

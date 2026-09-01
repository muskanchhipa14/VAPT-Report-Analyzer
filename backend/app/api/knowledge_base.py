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
    items = kb_service.get_all_items(db)
    for item in items:
        if not item.remediation and item.recommendations:
            item.remediation = item.recommendations
        if not item.recommendations and item.remediation:
            item.recommendations = item.remediation
    return items

@router.get("/{cwe_id}", response_model=KnowledgeBaseItemResponse)
def get_knowledge_base_item(cwe_id: str, db: Session = Depends(get_db)):
    item = kb_service.get_item_by_cwe(db, cwe_id)
    if not item and cwe_id.isdigit():
        from app.models.knowledge_base import KnowledgeBaseItem
        item = db.query(KnowledgeBaseItem).filter(KnowledgeBaseItem.id == int(cwe_id)).first()
        
    if not item:
        raise HTTPException(
            status_code=404,
            detail=f"Knowledge base item for {cwe_id} not found."
        )
        
    if not item.remediation and item.recommendations:
        item.remediation = item.recommendations
    if not item.recommendations and item.remediation:
        item.recommendations = item.remediation

    return item

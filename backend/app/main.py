from fastapi import FastAPI

from app.core.database import Base, engine
from app.api.knowledge_base import router as kb_router
from app.api.upload import router as upload_router

Base.metadata.create_all(bind=engine)

app = FastAPI(title="VAPT Report Analyzer")

app.include_router(kb_router)
app.include_router(upload_router)


@app.get("/")
def root():
    return {"message": "VAPT Report Analyzer API is Running"}
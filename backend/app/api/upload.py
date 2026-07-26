from fastapi import APIRouter, UploadFile, File

from app.services.pdf_parser import extract_text_from_pdf

router = APIRouter(
    prefix="/upload",
    tags=["PDF Upload"]
)


@router.post("/")
async def upload_pdf(file: UploadFile = File(...)):
    text = await extract_text_from_pdf(file)

    return {
        "filename": file.filename,
        "text": text
    }
from fastapi import UploadFile, HTTPException


MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


async def validate_pdf(file: UploadFile) -> bytes:
    """
    Validate uploaded file and return its contents.
    """

    # Check file extension
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="No file provided."
        )

    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(
            status_code=400,
            detail="Only PDF files are allowed."
        )

    # Read file contents
    contents = await file.read()

    # Check empty file
    if not contents:
        raise HTTPException(
            status_code=400,
            detail="Uploaded file is empty."
        )

    # Check file size
    if len(contents) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=400,
            detail="File size must be less than 10 MB."
        )

    # Check PDF file signature
    if not contents.startswith(b"%PDF"):
        raise HTTPException(
            status_code=400,
            detail="Invalid PDF file."
        )

    return contents
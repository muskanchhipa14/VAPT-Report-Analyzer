import fitz
from pathlib import Path


def extract_text_from_pdf(file_path: str) -> str:

    pdf_path = Path(file_path)

    if not pdf_path.exists():
        raise FileNotFoundError("PDF file not found.")

    document = fitz.open(str(pdf_path))

    extracted_text = []

    for page in document:
        text = page.get_text()

        if text:
            extracted_text.append(text)

    document.close()

    return "\n".join(extracted_text)
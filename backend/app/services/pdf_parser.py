from io import BytesIO
from pypdf import PdfReader


async def extract_text_from_pdf(file):
    content = await file.read()

    pdf = PdfReader(BytesIO(content))

    text = ""

    for page in pdf.pages:
        page_text = page.extract_text()

        if page_text:
            text += page_text + "\n"

    return text
import os
import tempfile

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.services.eml.analyzer import analyze_eml


MAX_EML_SIZE = 25 * 1024 * 1024


router = APIRouter(
    prefix="/api/eml",
    tags=["Email Analysis"],
)


@router.post("/analyze")
async def analyze_email(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="No filename provided.",
        )

    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported.",
        )

    # Read at most one byte over the limit instead of loading an
    # arbitrarily large upload into memory.
    file_bytes = await file.read(
        MAX_EML_SIZE + 1
    )

    if len(file_bytes) > MAX_EML_SIZE:
        raise HTTPException(
            status_code=413,
            detail="The .eml file exceeds the 25 MB limit.",
        )

    if not file_bytes:
        raise HTTPException(
            status_code=400,
            detail="The uploaded file is empty.",
        )

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            suffix=".eml",
            delete=False,
        ) as temp_file:
            temp_file.write(file_bytes)
            temp_path = temp_file.name

        result = analyze_eml(temp_path)

        result["email"]["filename"] = file.filename

        return {
            "status": "success",
            "result": result,
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to analyze the email file: {exc}",
        ) from exc

    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
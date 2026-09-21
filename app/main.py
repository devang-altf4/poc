"""FastAPI web application for Bulk PDF Digital Signing POC."""

import io
import time
import zipfile
import base64
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app.certs import cert_manager
from app.invoices import generate_sample_invoices, DATA_DIR, INPUT_DIR
from app.signing import (
    load_signer,
    sign_pdf_bytes,
    inspect_byte_range,
    verify_pdf,
    tamper_pdf,
)

OUTPUT_DIR = DATA_DIR / "output"
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


def _safe_path(folder: Path, filename: str) -> Path:
    """Join a client-supplied filename onto `folder`, refusing anything that
    could step outside it (e.g. '../demo-signer.pfx'). This app is deployed
    publicly, so filenames from requests are never trusted as paths."""
    name = Path(filename).name
    if not name or name != filename or name in (".", "..") or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    return folder / name

app = FastAPI(
    title="Bulk PDF Digital Signing POC",
    description="Live demonstration of automated digital invoice signing with pyHanko.",
    version="1.0.0",
)

# Initialize certs & directory structure on load
cert_manager.init_environment()

# Mount static files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class SignRequest(BaseModel):
    files: Optional[List[str]] = None
    use_timestamp: bool = False


@app.api_route("/healthz", methods=["GET", "HEAD"])
def healthz():
    """Cheap liveness probe for Render and UptimeRobot (which may send HEAD)."""
    return {"ok": True}


@app.get("/")
def serve_index():
    """Serves the single-page application UI."""
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/cert")
def get_certificate_details():
    """Returns metadata for the currently active signing certificate."""
    return cert_manager.get_active_info()


@app.post("/api/cert/upload")
def upload_certificate(file: UploadFile = File(...), password: str = Form("")):
    """Uploads a real PKCS#12 (.pfx) certificate and password."""
    if not file.filename.lower().endswith((".pfx", ".p12")):
        raise HTTPException(status_code=400, detail="Only .pfx and .p12 files are supported.")

    content = file.file.read()
    try:
        cert_manager.set_custom_certificate(content, password)
        return {"success": True, "cert": cert_manager.get_active_info()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to load PKCS#12 certificate: {e}")


@app.post("/api/cert/reset-demo")
def reset_to_demo_certificate():
    """Restores the default self-signed demo certificate."""
    cert_manager.reset_to_demo()
    return {"success": True, "cert": cert_manager.get_active_info()}


@app.post("/api/invoices/generate")
def generate_invoices():
    """Generates 10 sample uncompressed B2B tax invoices."""
    files = generate_sample_invoices(10)
    return {"success": True, "count": len(files), "files": files}


@app.post("/api/invoices/upload")
def upload_invoices(files: List[UploadFile] = File(...)):
    """Allows uploading one or more custom PDF invoices."""
    INPUT_DIR.mkdir(parents=True, exist_ok=True)
    saved = []
    for f in files:
        # keep only the base name so an upload can't write outside data/input
        name = Path(f.filename or "").name
        if not name.lower().endswith(".pdf"):
            continue
        dest = INPUT_DIR / name
        with open(dest, "wb") as out:
            out.write(f.file.read())
        saved.append(name)
    return {"success": True, "uploaded": saved}


@app.get("/api/invoices")
def list_invoices():
    """Lists all available input invoices and signed output invoices."""
    INPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    input_files = [f.name for f in sorted(INPUT_DIR.glob("*.pdf"))]
    signed_files = [f.name for f in sorted(OUTPUT_DIR.glob("*-signed.pdf"))]
    tampered_files = [f.name for f in sorted(OUTPUT_DIR.glob("*-TAMPERED.pdf"))]

    return {
        "inputs": input_files,
        "signed": signed_files,
        "tampered": tampered_files,
    }


@app.post("/api/sign")
def sign_invoices(req: SignRequest):
    """Bulk signs all or selected input PDFs."""
    INPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    targets = req.files
    if not targets:
        targets = [f.name for f in sorted(INPUT_DIR.glob("*.pdf"))]

    if not targets:
        raise HTTPException(status_code=400, detail="No PDF files available in input directory to sign.")

    # Load signer ONCE for the entire batch as per requirements
    try:
        signer = load_signer(cert_manager.active_pfx_path, cert_manager.active_password)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load signer: {e}")

    results = []
    start_time = time.perf_counter()

    for filename in targets:
        try:
            in_path = _safe_path(INPUT_DIR, filename)
        except HTTPException:
            results.append({"filename": filename, "success": False, "error": "Invalid filename"})
            continue
        if not in_path.exists():
            results.append({"filename": filename, "success": False, "error": "File not found"})
            continue

        out_name = f"{in_path.stem}-signed.pdf"
        out_path = OUTPUT_DIR / out_name

        try:
            with open(in_path, "rb") as f:
                pdf_bytes = f.read()

            signed_bytes = sign_pdf_bytes(
                pdf_bytes=pdf_bytes,
                signer=signer,
                use_timestamp=req.use_timestamp,
            )

            with open(out_path, "wb") as f:
                f.write(signed_bytes)

            results.append({
                "filename": filename,
                "signed_filename": out_name,
                "size": len(signed_bytes),
                "success": True,
            })
        except Exception as e:
            results.append({
                "filename": filename,
                "success": False,
                "error": str(e),
            })

    elapsed = time.perf_counter() - start_time
    successful_count = sum(1 for r in results if r.get("success"))

    return {
        "total_requested": len(targets),
        "successful_count": successful_count,
        "elapsed_seconds": round(elapsed, 3),
        "results": results,
    }


@app.get("/api/inspect/{filename}")
def inspect_file(filename: str):
    """Inspects /ByteRange structure and computes exact signed hash & placeholder padding."""
    file_path = _safe_path(OUTPUT_DIR, filename)
    if not file_path.exists():
        file_path = _safe_path(INPUT_DIR, filename)
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")

    with open(file_path, "rb") as f:
        data = f.read()

    try:
        info = inspect_byte_range(data)
        info["filename"] = filename
        return info
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Cannot inspect /ByteRange: {e}")


@app.post("/api/verify/{filename}")
def verify_file(filename: str):
    """Verifies digital signature on a specific PDF against the active trust root."""
    file_path = _safe_path(OUTPUT_DIR, filename)
    if not file_path.exists():
        file_path = _safe_path(INPUT_DIR, filename)
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")

    with open(file_path, "rb") as f:
        data = f.read()

    res = verify_pdf(data, cert_manager.active_pem_path)
    res["filename"] = filename
    return res


@app.post("/api/tamper/{filename}")
def tamper_file(filename: str):
    """Tampers with invoice total bytes in a signed PDF and runs verification comparison."""
    signed_path = _safe_path(OUTPUT_DIR, filename)
    if not signed_path.exists():
        raise HTTPException(status_code=404, detail="Signed file not found")

    with open(signed_path, "rb") as f:
        signed_bytes = f.read()

    # 1. Verify original first
    orig_verification = verify_pdf(signed_bytes, cert_manager.active_pem_path)
    orig_verification["filename"] = filename

    # 2. Tamper
    try:
        tampered_bytes, action = tamper_pdf(signed_bytes)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Tampering failed: {e}")

    # Base name for tampered file
    clean_stem = filename.replace("-signed.pdf", "").replace(".pdf", "")
    tampered_name = f"{clean_stem}-TAMPERED.pdf"
    tampered_path = OUTPUT_DIR / tampered_name

    with open(tampered_path, "wb") as f:
        f.write(tampered_bytes)

    # 3. Verify tampered
    tampered_verification = verify_pdf(tampered_bytes, cert_manager.active_pem_path)
    tampered_verification["filename"] = tampered_name

    return {
        "success": True,
        "action": action,
        "original": orig_verification,
        "tampered": tampered_verification,
    }


@app.get("/api/download-zip")
def download_zip():
    """Bundles all signed PDFs into a ZIP file for download."""
    signed_files = sorted(OUTPUT_DIR.glob("*-signed.pdf"))
    if not signed_files:
        raise HTTPException(status_code=400, detail="No signed PDF files available to download.")

    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in signed_files:
            zf.write(p, arcname=p.name)

    zip_bytes = zip_buf.getvalue()
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=signed-invoices.zip"},
    )


class PreviewRequest(BaseModel):
    folder: str
    filename: str


@app.post("/api/preview-bytes")
def get_preview_bytes(req: PreviewRequest):
    """Returns base64 encoded PDF bytes in JSON so download managers (IDM) cannot intercept."""
    if req.folder not in ("input", "output"):
        raise HTTPException(status_code=400, detail="Invalid folder")
    target = _safe_path(INPUT_DIR if req.folder == "input" else OUTPUT_DIR, req.filename)
    if not target.exists():
        raise HTTPException(status_code=404, detail="PDF not found")
    with open(target, "rb") as f:
        content = f.read()
    b64_data = base64.b64encode(content).decode("ascii")
    return {"filename": req.filename, "base64": b64_data}


@app.get("/api/pdf/{folder}/{filename}")
def view_raw_pdf(folder: str, filename: str):
    """Serves raw PDF file for viewing."""
    if folder not in ("input", "output"):
        raise HTTPException(status_code=400, detail="Invalid folder")
    target = _safe_path(INPUT_DIR if folder == "input" else OUTPUT_DIR, filename)
    if not target.exists():
        raise HTTPException(status_code=404, detail="PDF not found")
    return FileResponse(
        target,
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="{target.name}"'},
    )


@app.post("/api/reset")
def reset_all():
    """Resets input and output directories."""
    for folder in [INPUT_DIR, OUTPUT_DIR]:
        if folder.exists():
            for f in folder.glob("*.pdf"):
                try:
                    f.unlink()
                except Exception:
                    pass
    return {"success": True, "message": "Demo data reset successfully."}

from pathlib import Path

from fastapi import FastAPI, File, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app import scanner

BASE = Path(__file__).resolve().parent
MAX_BYTES = 25 * 1024 * 1024  # 25 MB

app = FastAPI(title="ANTVRS", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; img-src 'self' data:"
    )
    return response


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {"max_mb": MAX_BYTES // (1024 * 1024)})


@app.post("/scan", response_class=HTMLResponse)
async def scan(request: Request, file: UploadFile = File(...)):
    data = await file.read(MAX_BYTES + 1)
    max_mb = MAX_BYTES // (1024 * 1024)
    if len(data) > MAX_BYTES:
        return templates.TemplateResponse(
            request, "index.html",
            {"error": f"File is larger than {max_mb} MB.", "max_mb": max_mb},
            status_code=413,
        )
    if not data:
        return templates.TemplateResponse(
            request, "index.html",
            {"error": "That file is empty.", "max_mb": max_mb},
            status_code=400,
        )
    result = scanner.scan_bytes(file.filename or "unnamed", data)
    return templates.TemplateResponse(request, "result.html", {"r": result})


@app.get("/about", response_class=HTMLResponse)
async def about(request: Request):
    return templates.TemplateResponse(request, "about.html", {})


@app.get("/privacy", response_class=HTMLResponse)
async def privacy(request: Request):
    return templates.TemplateResponse(request, "privacy.html", {})
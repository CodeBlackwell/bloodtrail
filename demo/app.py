import json
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.gzip import GZipMiddleware

# Allow importing bloodtrail from parent directory
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from parser import parse_upload
from analyzer import analyze

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB
ALLOWED_EXTENSIONS = {".zip", ".json"}
UPLOAD_RATE_WINDOW = 3600  # 1 hour
UPLOAD_RATE_LIMIT = 3      # max uploads per window per IP

app = FastAPI(title="BloodTrail Demo")
app.add_middleware(GZipMiddleware, minimum_size=500)

# Per-IP upload rate tracking
_upload_times: dict[str, list[float]] = defaultdict(list)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    if request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=3600"
    return response

DEMO_DIR = Path(__file__).resolve().parent
SAMPLE_PATH = DEMO_DIR / "data" / "sample_ad.json"

_sample_data = None


def get_sample():
    global _sample_data
    if _sample_data is None:
        _sample_data = json.loads(SAMPLE_PATH.read_text())
    return _sample_data


def set_data(data):
    global _sample_data
    _sample_data = data


@app.get("/api/sample")
def api_sample():
    return get_sample()


def _check_rate_limit(client_ip: str):
    now = time.monotonic()
    times = _upload_times[client_ip]
    # Prune old entries
    _upload_times[client_ip] = [t for t in times if now - t < UPLOAD_RATE_WINDOW]
    if len(_upload_times[client_ip]) >= UPLOAD_RATE_LIMIT:
        raise HTTPException(429, "Upload rate limit exceeded. Try again later.")
    _upload_times[client_ip].append(now)


@app.post("/api/upload")
async def api_upload(request: Request, file: UploadFile):
    # Rate limit per IP
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    # Validate extension
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(400, f"Invalid file type. Allowed: {', '.join(ALLOWED_EXTENSIONS)}")

    # Read with size limit
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"File too large. Maximum size: {MAX_UPLOAD_BYTES // (1024*1024)} MB")

    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)
    try:
        parsed = parse_upload(tmp_path)
        result = analyze(parsed["nodes"], parsed["edges"])
        parsed["chains"] = result["chains"]
        parsed["quick_wins"] = result["quick_wins"]
        parsed["meta"]["chain_count"] = len(result["chains"])
        return parsed
    except Exception:
        raise HTTPException(422, "Failed to parse file. Ensure it is valid SharpHound output.")
    finally:
        tmp_path.unlink(missing_ok=True)


app.mount("/static", StaticFiles(directory=DEMO_DIR / "static"), name="static")


@app.get("/")
def index():
    return FileResponse(DEMO_DIR / "static" / "index.html")

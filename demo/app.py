import json
import sys
import tempfile
from pathlib import Path

from fastapi import FastAPI, Request, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.gzip import GZipMiddleware

# Allow importing bloodtrail from parent directory
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from parser import parse_upload
from analyzer import analyze

app = FastAPI(title="BloodTrail Demo")
app.add_middleware(GZipMiddleware, minimum_size=500)


@app.middleware("http")
async def cache_static(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=3600"
    return response

DEMO_DIR = Path(__file__).resolve().parent
SAMPLE_PATH = DEMO_DIR / "data" / "sample_ad.json"

# Cache sample data at startup
_sample_data = None


def get_sample():
    global _sample_data
    if _sample_data is None:
        _sample_data = json.loads(SAMPLE_PATH.read_text())
    return _sample_data


@app.get("/api/sample")
def api_sample():
    return get_sample()


@app.post("/api/upload")
async def api_upload(file: UploadFile):
    suffix = Path(file.filename).suffix
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(await file.read())
        tmp_path = Path(tmp.name)
    try:
        parsed = parse_upload(tmp_path)
        result = analyze(parsed["nodes"], parsed["edges"])
        parsed["chains"] = result["chains"]
        parsed["quick_wins"] = result["quick_wins"]
        parsed["meta"]["chain_count"] = len(result["chains"])
        return parsed
    finally:
        tmp_path.unlink(missing_ok=True)


app.mount("/static", StaticFiles(directory=DEMO_DIR / "static"), name="static")


@app.get("/")
def index():
    return FileResponse(DEMO_DIR / "static" / "index.html")

# BloodTrail — port 8008 (PROVE:7860, PANEL:8000, crackpedia:8006, kata:8007)
DEMO_PORT := "8008"

dev:
    -lsof -ti :{{DEMO_PORT}} | xargs kill -9 2>/dev/null
    cd demo && uvicorn app:app --reload --reload-dir static --reload-dir . --host 0.0.0.0 --port {{DEMO_PORT}}

build-sample:
    cd demo && python data/build_sample.py

install:
    pip install fastapi uvicorn python-multipart

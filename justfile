# BloodTrail — port 8008 (PROVE:7860, PANEL:8000, crackpedia:8006, kata:8007)
DEMO_PORT := "8008"

dev:
    -lsof -ti :{{DEMO_PORT}} | xargs kill -9 2>/dev/null
    uvicorn bloodtrail.demo.app:app --reload --reload-dir bloodtrail/demo/static --reload-dir bloodtrail/demo --host 0.0.0.0 --port {{DEMO_PORT}}

build-sample:
    cd bloodtrail/demo && python data/build_sample.py

install:
    pip install -e ".[ui]"

deploy:
    git push
    ssh root@5.78.198.79 'cd /opt/bloodtrail && git pull && docker compose -f docker-compose.prod.yml up -d --build'

publish:
    rm -rf dist/
    python -m build
    twine upload dist/*

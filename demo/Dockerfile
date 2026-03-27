FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY bloodtrail/ bloodtrail/
COPY demo/ demo/

RUN pip install --no-cache-dir ".[ui]" python-multipart

EXPOSE 8008
CMD ["uvicorn", "demo.app:app", "--host", "0.0.0.0", "--port", "8008"]

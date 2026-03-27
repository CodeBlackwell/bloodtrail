FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY bloodtrail/ bloodtrail/
COPY demo/ demo/

RUN pip install --no-cache-dir ".[ui]" python-multipart

WORKDIR /app/demo
EXPOSE 8008
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8008"]

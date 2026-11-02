FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY bloodtrail/ bloodtrail/

RUN pip install --no-cache-dir -c bloodtrail/demo/constraints.txt ".[ui]"

EXPOSE 8008
CMD ["uvicorn", "bloodtrail.demo.app:app", "--host", "0.0.0.0", "--port", "8008"]

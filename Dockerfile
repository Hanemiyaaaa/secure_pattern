FROM python:3.11-slim

WORKDIR /app

COPY backend /app/backend
COPY frontend /app/frontend
COPY backend/main.py /app/main.py

RUN pip install --no-cache-dir fastapi uvicorn[standard] sqlalchemy psycopg2-binary python-jose bcrypt requests

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
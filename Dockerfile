# code/Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Expose FastAPI port (Phase 5)
EXPOSE 8000

# Placeholder command — will be updated in Phase 5 to run FastAPI
CMD ["python", "main.py"]

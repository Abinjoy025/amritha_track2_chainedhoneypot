FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Build context is project root; requirements.txt lives there
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy entire project so all modules (soar/, blockchain/, ai_module/) are available
COPY . .

EXPOSE 8000
CMD ["python", "-m", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]

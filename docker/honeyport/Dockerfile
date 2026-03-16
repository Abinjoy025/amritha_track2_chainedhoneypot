FROM python:3.11-slim

WORKDIR /app

# Install OS deps for building Python packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies from project root requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy full project (app.py, templates/, soar/, blockchain/, ai_module/, etc.)
COPY . .

# Honeypot logs go here
RUN mkdir -p /logs

ENV HONEYPOT_HOST=0.0.0.0
ENV HONEYPOT_PORT=5000

EXPOSE 5000

CMD ["python", "app.py"]

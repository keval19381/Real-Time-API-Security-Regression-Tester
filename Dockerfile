FROM python:3.10-slim

ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    PORT=8000

WORKDIR /app

# Install system dependencies needed for Playwright Chromium
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    curl \
    gnupg \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy and install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browser and its OS-level system dependencies
RUN python -m playwright install --with-deps chromium

# Copy application source code
COPY . .

# Expose port (Render sets $PORT dynamically)
EXPOSE 8000

# Start both services via start.py
CMD ["python", "start.py"]

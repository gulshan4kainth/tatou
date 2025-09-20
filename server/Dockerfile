# Server image: minimal Flask + Gunicorn
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Copy project description, to instal dependencies
COPY pyproject.toml /app/pyproject.toml

# Install system dependencies required for building/installing Python packages
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# Install runtime dependencies
RUN pip install --no-cache-dir -e .

# Copy sources after dependencies installation
COPY src /app/src
RUN pip install --no-cache-dir -e .

EXPOSE 5000

# Default command runs the web server
CMD ["gunicorn", "-b", "0.0.0.0:5000", "server:app"]


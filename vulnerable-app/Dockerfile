# AI DAST Scanner - Custom Vulnerable Web Application
# Lightweight container for security testing with intentionally vulnerable endpoints
#
# Build: docker build -t vulnerable-app .
# Run:   docker run -p 8080:8080 vulnerable-app

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements first for Docker layer caching optimization
COPY requirements.txt .

# Install dependencies with no cache to reduce image size
RUN pip install --no-cache-dir -r requirements.txt

# Install curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Copy application files
COPY app.py .
COPY database.py .
COPY files/ ./files/

# Create data directory for SQLite database persistence
RUN mkdir -p /app/data

# Initialize database schema (creates DB in /app/data for volume mount persistence)
RUN python database.py

# Expose the application port
EXPOSE 8080

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

# Run the Flask application
CMD ["python", "app.py"]


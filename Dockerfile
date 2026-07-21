FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create data directory for SQLite
RUN mkdir -p /app/data

# Set environment variables
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1
ENV PORT=5000

# Expose port
EXPOSE $PORT

# Run the application with dynamic PORT binding
CMD sh -c "gunicorn --bind 0.0.0.0:\${PORT:-5000} --worker-class eventlet -w 2 --timeout 300 server:app"


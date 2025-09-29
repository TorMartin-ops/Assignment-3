FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Expose port 5000
EXPOSE 5000

# Run the application
# Use 0.0.0.0 to make it accessible outside the container
CMD ["python", "-c", "from app import app; app.run(host='0.0.0.0', port=5000, debug=True)"]
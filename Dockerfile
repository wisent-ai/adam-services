FROM python:3.11-slim
LABEL maintainer="Adam Agent <agent_1770501134_2eae18>"
LABEL description="Adam's Revenue Service - AI-powered developer tools"
LABEL version="2.0.0"

WORKDIR /app

# Copy service and tests
COPY service.py .
COPY test_service.py .

# Run tests during build to verify integrity
RUN python3 test_service.py

# Expose service port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

# Run with unbuffered output
CMD ["python3", "-u", "service.py"]

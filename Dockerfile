FROM python:3.11-slim
WORKDIR /app
COPY service.py .
EXPOSE 8080
CMD ["python3", "service.py"]

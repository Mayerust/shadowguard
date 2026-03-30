FROM python:3.11-slim

WORKDIR /app

# install flask ONLY (small, safe)
RUN pip install --no-cache-dir flask

# copy only the target app file (safe, isolated)
COPY target_app.py .

EXPOSE 8080

CMD ["python", "target_app.py"]

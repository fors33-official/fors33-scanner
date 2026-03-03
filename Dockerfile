# fors33-scanner: CLI-only image for CI/CD liability scans.
# Read-only; no file uploads out of the runner. Uses .f33 sidecars only.
FROM python:3.11-slim

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir .

ENTRYPOINT ["fors33-scanner"]
CMD ["--help"]


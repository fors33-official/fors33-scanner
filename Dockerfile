# fors33-scanner: CLI-only image for CI/CD liability scans.
# Build from the local open_source repo (source of truth), not PyPI.
FROM python:3.11-slim

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir .

ENTRYPOINT ["fors33-scanner"]
CMD ["--help"]


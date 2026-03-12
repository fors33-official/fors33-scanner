# fors33-scanner: CLI-only image for CI/CD liability scans.
# Read-only; no file uploads out of the runner. Uses .f33 sidecars only.
FROM python:3.11-slim-bookworm

WORKDIR /app

# Copy project files into the image.
COPY . .

# Enforce supply-chain hardening: install hash-locked dependencies, then remove build tooling.
COPY requirements-release.txt .
RUN pip install -r requirements-release.txt --require-hashes \
    && pip install --no-deps . \
    && pip uninstall -y pip setuptools wheel \
    && chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["--help"]


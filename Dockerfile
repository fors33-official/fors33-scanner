# fors33-scanner: CLI-only image for CI/CD liability scans.
# Read-only; no file uploads out of the runner. Uses .f33 sidecars only.
FROM python:3.11-slim

WORKDIR /app

# Copy project files into the image.
COPY . .

# Enforce supply-chain hardening: install hash-locked dependencies.
COPY requirements-release.txt .
RUN pip install -r requirements-release.txt --require-hashes

# Install the package itself without resolving additional dependencies.
RUN pip install --no-deps . && chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["--help"]


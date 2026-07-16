# Pin to multi-arch index digest. Update via:
#   docker pull python:3.13-slim && docker inspect python:3.13-slim --format='{{index .RepoDigests 0}}'
# or run scripts/update-docker-pins.sh
FROM python:3.13-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91

WORKDIR /app
COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements-dev.txt
COPY . .
ENV BASILISK_DEV_APPROVE=1
EXPOSE 8080
HEALTHCHECK CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')"
CMD ["python", "-m", "basilisk.serve", "--host", "0.0.0.0", "--port", "8080"]

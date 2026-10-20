# Pin to multi-arch index digest. Update via:
#   docker pull debian:bookworm-slim && docker inspect debian:bookworm-slim --format='{{index .RepoDigests 0}}'
# or run scripts/update-docker-pins.sh
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

ENV GNUPGHOME=/tmp/gnupg
RUN mkdir -p "$GNUPGHOME" && chmod 700 "$GNUPGHOME"

RUN apt-get update && apt-get install -y --no-install-recommends gnupg2 dirmngr ca-certificates \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]

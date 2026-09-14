# Pin to multi-arch index digest. Update via:
#   docker pull debian:bookworm-slim && docker inspect debian:bookworm-slim --format='{{index .RepoDigests 0}}'
# or run scripts/update-docker-pins.sh
FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

ENV GNUPGHOME=/tmp/gnupg
RUN mkdir -p "$GNUPGHOME" && chmod 700 "$GNUPGHOME"

RUN apt-get update && apt-get install -y --no-install-recommends gnupg2 dirmngr ca-certificates \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]

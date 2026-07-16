# Pin to multi-arch index digest. Update via:
#   docker pull debian:bookworm-slim && docker inspect debian:bookworm-slim --format='{{index .RepoDigests 0}}'
# or run scripts/update-docker-pins.sh
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

ENV GNUPGHOME=/tmp/gnupg
RUN mkdir -p "$GNUPGHOME" && chmod 700 "$GNUPGHOME"

RUN apt-get update && apt-get install -y --no-install-recommends gnupg2 dirmngr ca-certificates \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]

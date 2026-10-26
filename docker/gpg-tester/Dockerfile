# Pin to multi-arch index digest. Update via:
#   docker pull debian:bookworm-slim && docker inspect debian:bookworm-slim --format='{{index .RepoDigests 0}}'
# or run scripts/update-docker-pins.sh
FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8

ENV GNUPGHOME=/tmp/gnupg
RUN mkdir -p "$GNUPGHOME" && chmod 700 "$GNUPGHOME"

RUN apt-get update && apt-get install -y --no-install-recommends gnupg2 dirmngr ca-certificates \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]

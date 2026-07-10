FROM debian:bookworm-slim

ENV GNUPGHOME=/tmp/gnupg
RUN mkdir -p "$GNUPGHOME" && chmod 700 "$GNUPGHOME"

RUN apt-get update && apt-get install -y --no-install-recommends gnupg2 dirmngr ca-certificates \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]

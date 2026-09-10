FROM google/cloud-sdk:489.0.0-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
        ca-certificates \
        curl \
        gzip \
        gnupg \
    && install -d /usr/share/postgresql-common/pgdg \
    && curl --fail --show-error --silent \
        --output /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
        https://www.postgresql.org/media/keys/ACCC4CF8.asc \
    && printf '%s\n' \
        'deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main' \
        > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
        postgresql-client-18 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /workspace \
    && chown 65532:65532 /workspace

USER 65532:65532
WORKDIR /workspace

ENTRYPOINT ["/bin/bash"]

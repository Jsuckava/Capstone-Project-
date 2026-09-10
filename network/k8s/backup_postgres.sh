#!/usr/bin/env bash

set -Eeuo pipefail

required_variables=(
    PGHOST
    PGPORT
    PGUSER
    PGPASSWORD
    PGDATABASE
    POSTGRES_BACKUP_GCS_BUCKET
    POSTGRES_BACKUP_ENCRYPTION_KEY
)

for variable in "${required_variables[@]}"; do
    if [[ -z "${!variable:-}" ]]; then
        echo "ERROR: Required backup setting ${variable} is missing." >&2
        exit 1
    fi
done

for command_name in pg_dump gzip gpg gcloud sha256sum; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "ERROR: Required backup command ${command_name} is unavailable." >&2
        exit 1
    fi
done

bucket="${POSTGRES_BACKUP_GCS_BUCKET#gs://}"
bucket="${bucket%/}"
if [[ -z "$bucket" || "$bucket" == */* ]]; then
    echo "ERROR: POSTGRES_BACKUP_GCS_BUCKET must contain one GCS bucket name." >&2
    exit 1
fi

backup_root="$(mktemp -d /tmp/blockgo-postgres-backup.XXXXXX)"
passphrase_file="${backup_root}/passphrase"
cleanup() {
    rm -rf -- "$backup_root"
}
trap cleanup EXIT

umask 077
printf '%s' "$POSTGRES_BACKUP_ENCRYPTION_KEY" > "$passphrase_file"

timestamp="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
safe_database="$(printf '%s' "$PGDATABASE" | tr -cs 'A-Za-z0-9._-' '_')"
archive_name="blockgo-${safe_database}-${timestamp}.sql.gz"
compressed_path="${backup_root}/${archive_name}"
encrypted_path="${compressed_path}.gpg"
checksum_path="${encrypted_path}.sha256"
object_prefix="postgres/${safe_database}/${timestamp}"

echo "Creating PostgreSQL backup for ${PGDATABASE} at ${PGHOST}:${PGPORT}..."
pg_dump \
    --format=plain \
    --clean \
    --if-exists \
    --no-owner \
    --no-privileges \
    --host="$PGHOST" \
    --port="$PGPORT" \
    --username="$PGUSER" \
    --dbname="$PGDATABASE" \
    | gzip --best > "$compressed_path"

if [[ ! -s "$compressed_path" ]]; then
    echo "ERROR: pg_dump produced an empty backup." >&2
    exit 1
fi

gpg \
    --batch \
    --yes \
    --pinentry-mode loopback \
    --passphrase-file "$passphrase_file" \
    --symmetric \
    --cipher-algo AES256 \
    --compress-algo none \
    --output "$encrypted_path" \
    "$compressed_path"

rm -f -- "$compressed_path" "$passphrase_file"
(cd "$backup_root" && sha256sum "$(basename "$encrypted_path")" > "$(basename "$checksum_path")")

destination="gs://${bucket}/${object_prefix}/"
echo "Uploading encrypted backup to ${destination}..."
gcloud storage cp --quiet "$encrypted_path" "$checksum_path" "$destination"
echo "Encrypted PostgreSQL backup uploaded successfully: ${destination}$(basename "$encrypted_path")"

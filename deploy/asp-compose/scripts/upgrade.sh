#!/bin/sh
set -eu
umask 077

RELEASE_REPOSITORY="${ASP_RELEASE_REPOSITORY:-FunnyWolf/agentic-soc-platform}"
MANAGED_PATHS="compose.yaml .env.example README.md README.zh.md scripts"

usage() {
    cat <<'EOF'
Usage: ./scripts/upgrade.sh --version <version>

Downloads and verifies the matching ASP Compose release package, updates
release-managed files and image tags, runs migrations, starts services, and
checks the deployment.
EOF
}

version=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --version)
            version="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [ -z "$version" ]; then
    echo "--version is required." >&2
    usage >&2
    exit 1
fi

if [ "${#version}" -gt 128 ] || ! printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.-]*$'; then
    echo "Unsupported version format: $version" >&2
    exit 1
fi

for command_name in curl tar docker mktemp stat; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "Required command is not available: $command_name" >&2
        exit 1
    fi
done

if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    echo "sha256sum or shasum is required to verify release assets." >&2
    exit 1
fi

deployment_dir="$(pwd)"
if [ ! -f "$deployment_dir/compose.yaml" ] || [ ! -f "$deployment_dir/.env" ]; then
    echo "Run this script from an initialized ASP Compose deployment directory." >&2
    exit 1
fi

archive_name="asp-compose-$version.tar.gz"
checksum_name="$archive_name.sha256"
release_base_url="https://github.com/$RELEASE_REPOSITORY/releases/download/v$version"
work_dir="$(mktemp -d)"
stage_dir="$deployment_dir/.asp-upgrade-stage-$$"

cleanup() {
    rm -rf "$work_dir" "$stage_dir"
}
trap cleanup EXIT HUP INT TERM

verify_checksum() {
    directory="$1"
    checksum_file="$2"
    artifact="$3"

    if command -v sha256sum >/dev/null 2>&1; then
        (
            cd "$directory"
            sha256sum -c "$checksum_file"
        )
        return
    fi

    expected="$(awk 'NR == 1 {print $1}' "$directory/$checksum_file")"
    actual="$(shasum -a 256 "$directory/$artifact" | awk '{print $1}')"
    if [ -z "$expected" ] || [ "$actual" != "$expected" ]; then
        echo "SHA-256 verification failed for $artifact." >&2
        return 1
    fi
    echo "$artifact: OK"
}

create_compose_override() {
    if [ -e "$deployment_dir/compose.override.yaml" ]; then
        return
    fi

    cat > "$deployment_dir/compose.override.yaml" <<'EOF'
# User-managed Docker Compose overrides.
# ASP upgrades never overwrite this file.
# Keep supported passwords, ports, and image settings in .env.
# Replace the empty services mapping below when service-level overrides are needed.
#
# services:
#   asp-web:
#     environment:
#       EXAMPLE_SETTING: value
services: {}
EOF
}

image_with_version() {
    key="$1"
    line_count="$(grep -c "^${key}=" "$deployment_dir/.env" || true)"
    if [ "$line_count" -ne 1 ]; then
        echo ".env must contain exactly one ${key}= entry." >&2
        return 1
    fi

    image="$(grep "^${key}=" "$deployment_dir/.env" | cut -d= -f2-)"
    case "$image" in
        *@sha256:*)
            echo "$key uses a digest and cannot be updated automatically: $image" >&2
            return 1
            ;;
        *:*)
            repository="${image%:*}"
            current_tag="${image##*:}"
            if [ -z "$repository" ] || [ -z "$current_tag" ] || printf '%s' "$current_tag" | grep -q '/'; then
                echo "Cannot safely update $key image reference: $image" >&2
                return 1
            fi
            printf '%s:%s\n' "$repository" "$version"
            ;;
        *)
            echo "$key image reference must include a tag: $image" >&2
            return 1
            ;;
    esac
}

set_env_value() {
    key="$1"
    value="$2"
    temporary_env="$stage_dir/.env"
    temporary_content="$stage_dir/.env-content"
    env_mode="$(stat -c '%a' "$deployment_dir/.env" 2>/dev/null || stat -f '%Lp' "$deployment_dir/.env")"

    cp -p "$deployment_dir/.env" "$temporary_env"
    awk -v key="$key" -v value="$value" '
        index($0, key "=") == 1 { print key "=" value; next }
        { print }
    ' "$deployment_dir/.env" > "$temporary_content"
    cat "$temporary_content" > "$temporary_env"
    chmod "$env_mode" "$temporary_env"
    rm -f "$temporary_content"
    mv "$temporary_env" "$deployment_dir/.env"
}

backup_path() {
    path="$1"
    if [ -e "$deployment_dir/$path" ]; then
        printf '%s\n' "$path" >> "$backup_dir/original-paths"
        cp -a "$deployment_dir/$path" "$backup_dir/$path"
    fi
}

restore_pre_migration_files() {
    echo "Restoring release-managed files from $backup_dir" >&2
    for path in $MANAGED_PATHS .env; do
        rm -rf "$deployment_dir/$path"
    done
    while IFS= read -r path; do
        cp -a "$backup_dir/$path" "$deployment_dir/$path"
    done < "$backup_dir/original-paths"
}

apply_managed_files() {
    mkdir -p "$stage_dir"
    for path in $MANAGED_PATHS; do
        cp -a "$package_dir/$path" "$stage_dir/$path" || return 1
    done

    for path in $MANAGED_PATHS; do
        rm -rf "$deployment_dir/$path" || return 1
        mv "$stage_dir/$path" "$deployment_dir/$path" || return 1
    done
}

echo "Downloading ASP Compose $version release assets..."
curl -fL --retry 3 -o "$work_dir/$archive_name" "$release_base_url/$archive_name"
curl -fL --retry 3 -o "$work_dir/$checksum_name" "$release_base_url/$checksum_name"
verify_checksum "$work_dir" "$checksum_name" "$archive_name"

mkdir -p "$work_dir/unpacked"
tar -xzf "$work_dir/$archive_name" -C "$work_dir/unpacked"
package_dir="$work_dir/unpacked/asp-compose"

for path in $MANAGED_PATHS; do
    if [ ! -e "$package_dir/$path" ]; then
        echo "Release package is missing managed path: $path" >&2
        exit 1
    fi
done

for key in ASP_BACKEND_IMAGE ASP_FRONTEND_IMAGE; do
    packaged_image="$(grep "^${key}=" "$package_dir/.env.example" | cut -d= -f2-)"
    case "$packaged_image" in
        *:"$version")
            ;;
        *)
            echo "Release package $key does not use target version $version: $packaged_image" >&2
            exit 1
            ;;
    esac
done

backend_image="$(image_with_version ASP_BACKEND_IMAGE)"
frontend_image="$(image_with_version ASP_FRONTEND_IMAGE)"

create_compose_override

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_dir="$deployment_dir/backups/upgrade-$version-$timestamp-$$"
mkdir -p "$backup_dir"
: > "$backup_dir/original-paths"
for path in $MANAGED_PATHS .env; do
    backup_path "$path"
done

pre_migration_update() {
    apply_managed_files || return 1
    set_env_value ASP_BACKEND_IMAGE "$backend_image" || return 1
    set_env_value ASP_FRONTEND_IMAGE "$frontend_image" || return 1
    (
        cd "$deployment_dir"
        docker compose config --quiet
    ) || return 1
    (
        cd "$deployment_dir"
        docker compose pull
    ) || return 1
}

if ! pre_migration_update; then
    restore_pre_migration_files
    echo "Upgrade stopped before database migration. No migration was attempted." >&2
    exit 1
fi

echo "Release files and images are ready. Starting database migration..."
if ! (
    cd "$deployment_dir"
    docker compose run --rm asp-migrate
); then
    echo "Database migration failed after release files were updated." >&2
    echo "Automatic downgrade is disabled after migration starts. Backup: $backup_dir" >&2
    exit 1
fi

if ! (
    cd "$deployment_dir"
    docker compose up -d
); then
    echo "Service startup failed after database migration." >&2
    echo "Automatic downgrade is disabled after migration starts. Backup: $backup_dir" >&2
    exit 1
fi

if ! (
    cd "$deployment_dir"
    ./scripts/doctor.sh
); then
    echo "Post-upgrade checks failed." >&2
    echo "Automatic downgrade is disabled after migration starts. Backup: $backup_dir" >&2
    exit 1
fi

echo "ASP upgraded to $version."
echo "Release file backup: $backup_dir"

#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: deploy/package-asp-compose.sh --version <version> [--output-dir <dir>] [--backend-image <image>] [--frontend-image <image>]
EOF
}

version=""
output_dir="dist"
backend_image=""
frontend_image=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      version="${2:-}"
      shift 2
      ;;
    --output-dir)
      output_dir="${2:-}"
      shift 2
      ;;
    --backend-image)
      backend_image="${2:-}"
      shift 2
      ;;
    --frontend-image)
      frontend_image="${2:-}"
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
  echo "--version is required" >&2
  usage >&2
  exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$script_dir/.." && pwd)"
source_dir="$script_dir/asp-compose"
dist_dir="$root/$output_dir"
staging="$dist_dir/asp-compose"
archive_path="$dist_dir/asp-compose-$version.tar.gz"
archive_checksum_path="$archive_path.sha256"
upgrade_script_name="asp-upgrade-$version.sh"
upgrade_script_path="$dist_dir/$upgrade_script_name"
upgrade_checksum_path="$upgrade_script_path.sha256"

rm -rf "$staging"
mkdir -p "$dist_dir"
cp -a "$source_dir" "$staging"
rm -f "$staging/.env"
chmod +x "$staging"/scripts/*.sh

env_example="$staging/.env.example"
if [ -n "$backend_image" ]; then
  sed -i -E "s|^ASP_BACKEND_IMAGE=.*|ASP_BACKEND_IMAGE=$backend_image|" "$env_example"
else
  sed -i -E "s|^(ASP_BACKEND_IMAGE=.*:).*$|\1$version|" "$env_example"
fi

if [ -n "$frontend_image" ]; then
  sed -i -E "s|^ASP_FRONTEND_IMAGE=.*|ASP_FRONTEND_IMAGE=$frontend_image|" "$env_example"
else
  sed -i -E "s|^(ASP_FRONTEND_IMAGE=.*:).*$|\1$version|" "$env_example"
fi

rm -f "$archive_path"
tar -czf "$archive_path" -C "$dist_dir" asp-compose
(
  cd "$dist_dir"
  sha256sum "$(basename "$archive_path")" > "$(basename "$archive_checksum_path")"
)

cp "$source_dir/scripts/upgrade.sh" "$upgrade_script_path"
chmod +x "$upgrade_script_path"
(
  cd "$dist_dir"
  sha256sum "$upgrade_script_name" > "$(basename "$upgrade_checksum_path")"
)

echo "Created $archive_path"
echo "Created $archive_checksum_path"
echo "Created $upgrade_script_path"
echo "Created $upgrade_checksum_path"

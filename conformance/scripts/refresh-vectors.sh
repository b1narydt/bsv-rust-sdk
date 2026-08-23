#!/usr/bin/env bash
# Refresh vendored conformance assets from upstream ts-stack.
#
# Usage:
#   ./conformance/scripts/refresh-vectors.sh             # latest main
#   ./conformance/scripts/refresh-vectors.sh <sha|ref>   # pin a commit/ref

set -euo pipefail

UPSTREAM_REPO="bsv-blockchain/ts-stack"
DEFAULT_REF="main"
REF="${1:-$DEFAULT_REF}"

CONFORMANCE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE_FILE="$CONFORMANCE_DIR/SOURCE"
TRACKED_FILE="$CONFORMANCE_DIR/TRACKED_FILES"

if [[ ! -f "$TRACKED_FILE" ]]; then
  echo "ERROR: tracked-file manifest not found: $TRACKED_FILE" >&2
  exit 1
fi

# Resolve ref -> full commit SHA so SOURCE always records an immutable pin.
SHA="$(
  curl -fsSL \
    -H 'Accept: application/vnd.github+json' \
    "https://api.github.com/repos/${UPSTREAM_REPO}/commits/${REF}" \
    | python3 -c 'import json, sys; print(json.load(sys.stdin).get("sha", ""))'
)"

if [[ ! "$SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "ERROR: could not resolve $UPSTREAM_REPO@$REF to a commit SHA" >&2
  exit 1
fi

echo "Pinning to ${UPSTREAM_REPO}@${SHA} (ref: ${REF})"

while IFS= read -r path || [[ -n "$path" ]]; do
  [[ -z "$path" || "$path" == \#* ]] && continue
  if [[ "$path" == /* || "$path" == *".."* ]]; then
    echo "ERROR: unsafe tracked path: $path" >&2
    exit 1
  fi

  url="https://raw.githubusercontent.com/${UPSTREAM_REPO}/${SHA}/conformance/${path}"
  dest="$CONFORMANCE_DIR/$path"
  tmp="${dest}.tmp"
  mkdir -p "$(dirname "$dest")"
  echo "  $path"
  curl -fsSL "$url" -o "$tmp"
  mv "$tmp" "$dest"
done < "$TRACKED_FILE"

cat > "$SOURCE_FILE" <<EOF
# Upstream conformance vector pin.
# Update via ./conformance/scripts/refresh-vectors.sh
upstream_repo=${UPSTREAM_REPO}
upstream_sha=${SHA}
upstream_ref=${REF}
fetched_at=$(date -u +%Y-%m-%d)
EOF

"$CONFORMANCE_DIR/scripts/generate-coverage.py"

echo "Done. Re-run the Rust conformance tests before committing."

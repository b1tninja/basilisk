#!/usr/bin/env bash
# Build the Vite portal and print the dist directory path.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WEB_DIR="${REPO_ROOT}/web"
OUT="${WEB_DIR}/dist"

if [[ ! -f "${WEB_DIR}/package.json" ]]; then
  echo "Missing web/package.json" >&2
  exit 1
fi

if [[ ! -d "${WEB_DIR}/node_modules" ]]; then
  (cd "$WEB_DIR" && npm ci) >&2
fi

(cd "$WEB_DIR" && npm run build) >&2

# ── The signalling origin the deployed pages must allow ──────────────────────
# A browser enforces the *intersection* of the document's `<meta>` policy and
# the response header, and Front Door overwrites the header with a policy that
# names this deployment's Web PubSub host. The built HTML cannot know that host
# — it differs per deployment — so it is merged in here, into the artifact that
# gets uploaded.
#
# It used to be merged per request by `basilisk/portal/static.py`. That covers a
# route the deployed site does not take: Front Door sends `/*` to the storage
# account's `$web` container and only `/api/*`, `/pks/*`, `/claim/*`, `/.auth/*`
# and `/health` to the Function App. So the portal HTML was served straight from
# blob storage with a meta that had no `wss://` in it, the header had one, the
# intersection was empty for that source, and shared sessions could not open a
# socket on the deployed site at all.
#
# Before the clean-URL aliases below, deliberately: `/toolkit` is served by the
# *extensionless* blob, which is a copy of `toolkit.html`. Injecting after the
# copy would fix the page nobody fetches and leave the one they do.
BASILISK_SIGNALING_WSS_ORIGIN="${BASILISK_SIGNALING_WSS_ORIGIN:-}"
python - "$OUT" "$REPO_ROOT" "$BASILISK_SIGNALING_WSS_ORIGIN" >&2 <<'PY'
import sys
from pathlib import Path

dist, repo_root, origin = Path(sys.argv[1]), sys.argv[2], sys.argv[3].strip()

if origin == "none":
    # The deliberate case, spelled the way `rtc.ice stun=none` spells it: a
    # deployment that has no signalling at all. Nothing to merge, and the log
    # line says a person chose this rather than that a lookup came back empty.
    print("signalling: explicitly none — pages will allow no signalling socket")
    raise SystemExit(0)

if not origin:
    # Unset is a failure, not a default. It was a warning one layer up and that
    # is how a site shipped with shared sessions silently off: an empty string
    # is what every failed lookup produces, and "no signalling" and "we could
    # not find out" are not the same claim. Only one of them is safe to guess,
    # and it is not this one.
    #
    # A build run by hand (`npm run build`) never reaches here — this script is
    # the packaging step for a deploy, and a deploy has a deployment to ask.
    print(
        "signalling: BASILISK_SIGNALING_WSS_ORIGIN is unset.\n"
        "  These pages would upload with a policy that vetoes the connect-src\n"
        "  header Front Door sends, and shared sessions would not work.\n"
        "  Set it to wss://<host>, or to `none` if this deployment has no\n"
        "  signalling at all.",
        file=sys.stderr,
    )
    raise SystemExit(1)

sys.path.insert(0, repo_root)
from basilisk.security.csp import connect_src_sources, merge_connect_src

failed = []
for html in sorted(dist.glob("*.html")):
    text = html.read_text(encoding="utf-8")
    merged = merge_connect_src(text, (origin,))
    if merged != text:
        html.write_text(merged, encoding="utf-8")
    # Verified rather than assumed. A page whose meta the regex did not match
    # would be silently skipped, and the failure it causes appears only in a
    # browser on the deployed site — which is exactly how this shipped.
    if origin not in connect_src_sources(merged):
        failed.append(html.name)

if failed:
    print("signalling: FAILED to merge the origin into:", file=sys.stderr)
    for name in failed:
        print(f"  - {name}", file=sys.stderr)
    print(
        "  These pages would be uploaded with a policy that vetoes the header "
        "Front Door sends, and shared sessions would not work.",
        file=sys.stderr,
    )
    raise SystemExit(1)

print(f"signalling OK: {origin} allowed by {len(list(dist.glob('*.html')))} page(s)")
PY

# Integrity contract (do not weaken):
#   - Entry scripts/styles/modulepreloads carry integrity= from vite-plugin-sri-gen.
#   - Module-graph / worker SRI lives in an *external* importmap JSON under
#     /importmaps/ (see web/scripts/externalize-importmaps.js). CSP is
#     script-src 'self' 'wasm-unsafe-eval' (no unsafe-eval / unsafe-inline).
#     The wasm keyword is only for OpenPGP.js Argon2; the WASM bytes are
#     embedded in an SRI-pinned JS chunk (see basilisk/serve.py _CSP comment).
#     Never strip those maps; browsers refuse to load a
#     module whose bytes ≠ the hash (CDN cache skew or tampering). Mixing old
#     and new chunks must fail closed.
python - "$OUT" >&2 <<'PY'
from pathlib import Path
import sys

dist = Path(sys.argv[1])
errors = []
html_files = list(dist.glob("*.html"))
if not html_files:
    errors.append("no HTML files in dist/")

for html in html_files:
    text = html.read_text(encoding="utf-8")
    if 'type="importmap"' not in text and "type='importmap'" not in text:
        errors.append(f"{html.name}: missing importmap (module-graph SRI)")
    if "<script type=\"importmap\">{" in text:
        errors.append(
            f"{html.name}: inline importmap still present — "
            "externalize-importmaps plugin did not run"
        )
    if "integrity=" not in text:
        errors.append(f"{html.name}: missing integrity= attributes")

importmaps = list((dist / "importmaps").glob("importmap-*.json")) if (dist / "importmaps").is_dir() else []
if not importmaps:
    errors.append("no /importmaps/importmap-*.json files written")

pin = dist / "integrity" / "module-roots.json"
if not pin.is_file():
    errors.append("missing /integrity/module-roots.json (Merkle pin)")
else:
    for html in html_files:
        text = html.read_text(encoding="utf-8")
        if 'name="basilisk-integrity-pins"' not in text:
            errors.append(f"{html.name}: missing basilisk-integrity-pins meta")

if errors:
    print("Integrity packaging checks FAILED:", file=sys.stderr)
    for e in errors:
        print(f"  - {e}", file=sys.stderr)
    sys.exit(1)

print(
    f"integrity OK: {len(html_files)} HTML page(s), "
    f"{len(importmaps)} external importmap(s), "
    f"module-roots pin={'yes' if pin.is_file() else 'no'}"
)
PY

# Clean URL aliases without .html suffix (Azure static website / Front Door).
# index.html is served at / and also aliased as /search; every other *.html
# page gets a matching extensionless blob so /page resolves without a 404.
cp "${OUT}/index.html" "${OUT}/search"
shopt -s nullglob
for html in "${OUT}"/*.html; do
  base="$(basename "$html" .html)"
  [[ "$base" == "index" ]] && continue
  cp "$html" "${OUT}/${base}"
done

# Only the dist path is printed to stdout — callers capture it with $().
echo "$OUT"

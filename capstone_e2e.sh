#!/usr/bin/env bash
# Capstone E2E smoke test using curl
# Works against GOOD (:8080) and (optionally) BAD (:8081) servers.
# Requirements: curl, jq, and either python or openssl.

set -euo pipefail

GOOD_BASE="${GOOD_BASE:-http://localhost:8080}"
BAD_BASE="${BAD_BASE:-http://localhost:8081}"
EMAIL="${EMAIL:-amy@example.com}"
PASS="${PASS:-p@ssw0rd}"

# --- prereqs -----------------------------------------------------------------
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing required tool: $1" >&2; exit 1; }; }
need curl
need jq

have_python=0; command -v python >/dev/null 2>&1 && have_python=1
have_ossl=0; command -v openssl >/dev/null 2>&1 && openssl dgst -help 2>&1 | grep -q -- -macopt && have_ossl=1

if (( ! have_python && ! have_ossl )); then
  echo "Need either python or openssl (with -macopt) for HMAC signing." >&2
  exit 1
fi

# --- helpers -----------------------------------------------------------------
TMPDIR_="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_"' EXIT

log() { printf "\n\033[1m%s\033[0m\n" "$*"; }
sub() { printf "  %s\n" "$*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

# Sign message (ts + "\n" + body) with hex key → hex digest (no prefix).
sign_hmac_sha256_hex() {
  local hexkey="$1" msg="$2"
  if (( have_python )); then
    python - "$hexkey" "$msg" <<'PY'
import sys,hmac,hashlib,binascii
hexkey,msg=sys.argv[1],sys.argv[2]
key=binascii.unhexlify(hexkey)
print(hmac.new(key,msg.encode(),hashlib.sha256).hexdigest())
PY
  elif (( have_ossl )); then
    # openssl wants the key in hex via -macopt hexkey:<hex>
    printf '%s' "$msg" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$hexkey" -r | awk '{print $1}'
  fi
}

http() { # method url [json-body] [extra curl args...]; writes BODY & CODE
  local method="$1" url="$2" body="${3-}"
  shift 2
  local extra=( "$@" )
  if [[ -n "$body" ]]; then
    resp="$(curl -sS -w $'\n%{http_code}' -X "$method" "$url" -H 'content-type: application/json' -d "$body" "${extra[@]}")"
  else
    resp="$(curl -sS -w $'\n%{http_code}' -X "$method" "$url" "${extra[@]}")"
  fi
  printf '%s' "$(sed '$d' <<<"$resp")" > "$TMPDIR_/body"
  tail -n1 <<<"$resp" > "$TMPDIR_/code"
}

body_json() { jq -r "$1" < "$TMPDIR_/body"; }
code_is()   { [[ "$(cat "$TMPDIR_/code")" == "$1" ]]; }

# --- flow --------------------------------------------------------------------

log "1) Signup (idempotent – ok if already exists)"
http POST "$GOOD_BASE/demo/signup" "$(jq -cn --arg e "$EMAIL" --arg p "$PASS" '{email:$e,password:$p}')" || true
sub "status: $(cat "$TMPDIR_/code")"
sub "body  : $(cat "$TMPDIR_/body")"

log "2) Login to get JWT"
http POST "$GOOD_BASE/auth/login" "$(jq -cn --arg e "$EMAIL" --arg p "$PASS" '{email:$e,password:$p}')"
code_is 200 || die "login failed: $(cat "$TMPDIR_/code") $(cat "$TMPDIR_/body")"
TOK="$(body_json '.token')"
[[ -n "$TOK" && "$TOK" != "null" ]] || die "no token in response"
sub "token: ${TOK:0:20}..."

log "3) Create a note with Idempotency-Key, then replay (should return SAME id)"
TS="$(date +%s)"
TITLE="hello-$TS"
BODYTXT="world-$TS"
CREATE_JSON="$(jq -cn --arg t "$TITLE" --arg b "$BODYTXT" '{title:$t,body:$b}')"

http POST "$GOOD_BASE/notes" "$CREATE_JSON" -H "Authorization: Bearer $TOK" -H "Idempotency-Key: cap-$TS"
code_is 200 || code_is 201 || die "create failed: $(cat "$TMPDIR_/code") $(cat "$TMPDIR_/body")"
ID1="$(body_json '.id')"
sub "create id: $ID1"

http POST "$GOOD_BASE/notes" "$CREATE_JSON" -H "Authorization: Bearer $TOK" -H "Idempotency-Key: cap-$TS"
code_is 200 || code_is 201 || die "replay failed"
ID2="$(body_json '.id')"
[[ "$ID2" == "$ID1" ]] || die "idempotency mismatch ($ID1 vs $ID2)"
sub "replay id: $ID2 (same ✔)"

log "4) Search notes by TITLE (should find exactly one)"
http GET "$GOOD_BASE/notes?q=$TITLE" "" -H "Authorization: Bearer $TOK"
code_is 200 || die "search failed"
COUNT="$(jq 'length' < "$TMPDIR_/body")"
[[ "$COUNT" -eq 1 ]] || die "want 1 note, got $COUNT"
sub "results: $COUNT ✔"
sub "$(jq -c '.[0]' < "$TMPDIR_/body")"

log "5) Register webhook secret (JWT-protected)"
http POST "$GOOD_BASE/hooks/register" "" -H "Authorization: Bearer $TOK"
code_is 200 || die "register secret failed"
SECRET_HEX="$(body_json '.secret')"
[[ "$SECRET_HEX" =~ ^[0-9a-fA-F]+$ ]] || die "invalid secret: $SECRET_HEX"
sub "secret (hex): ${SECRET_HEX:0:12}..."

log "6) Send a SIGNED webhook → should be accepted and create a note"
WTS="$(date +%s)"
WH_BODY='{"event":"cap","msg":"ok"}'
SIG_HEX="$(sign_hmac_sha256_hex "$SECRET_HEX" "$WTS"$'\n'"$WH_BODY")"
http POST "$GOOD_BASE/hooks/ingest/$EMAIL" "$WH_BODY" \
  -H "X-Timestamp: $WTS" -H "X-Signature: sha256=$SIG_HEX" -H 'content-type: application/json'
code_is 200 || die "webhook failed: $(cat "$TMPDIR_/code") $(cat "$TMPDIR_/body")"
sub "webhook ok: $(cat "$TMPDIR_/body")"

log "7) SSRF guard: GOOD should block loopback/private"
http GET "$GOOD_BASE/ssrf/fetch?url=http://127.0.0.1:9999/" ""
if code_is 200; then
  die "expected SSRF block (400), got 200"
fi
sub "blocked ✔ (status $(cat "$TMPDIR_/code")): $(cat "$TMPDIR_/body")"

log "8) Audit trail (JWT-protected) returns recent events"
http GET "$GOOD_BASE/admin/audit?limit=5" "" -H "Authorization: Bearer $TOK"
code_is 200 || die "audit list failed"
ALEN="$(jq 'length' < "$TMPDIR_/body")"
[[ "$ALEN" -ge 1 ]] || die "no audit events"
sub "audit events: $ALEN"
sub "$(jq -c '.[0]' < "$TMPDIR_/body")"

log "9) Dependency inventory (JWT-protected) returns modules"
http GET "$GOOD_BASE/admin/deps" "" -H "Authorization: Bearer $TOK"
code_is 200 || die "deps list failed"
DLEN="$(jq 'length' < "$TMPDIR_/body")"
[[ "$DLEN" -ge 1 ]] || die "deps empty"
sub "deps entries: $DLEN"
sub "$(jq -c '.[0]' < "$TMPDIR_/body")"

# --- optional BAD SSRF demo --------------------------------------------------
if curl -sS -o /dev/null -w "%{http_code}" "$BAD_BASE/ssrf/fetch_bad?url=$BAD_BASE/debug/pprof/" | grep -qE '^(200|302)$'; then
  log "10) BAD SSRF: fetch internal pprof via proxy (should SUCCEED here)"
  curl -s "$BAD_BASE/ssrf/fetch_bad?url=$BAD_BASE/debug/pprof/" | head -n 5
else
  sub "(skipping BAD SSRF demo; BAD server not reachable or route not mounted)"
fi

log "✅ ALL CHECKS PASSED"

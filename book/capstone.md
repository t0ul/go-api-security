# GOOD
go run ./cmd/api
# BAD
go run ./cmd/badapi

# JWT + note
TOK=$(curl -s -X POST :8080/auth/login -H 'content-type: application/json' -d '{"email":"amy@example.com","password":"p@ssw0rd"}' | jq -r .token)
curl -s -H "Authorization: Bearer $TOK" -H 'content-type: application/json' -H 'Idempotency-Key: cap-1' -d '{"title":"cap","body":"stone"}' :8080/notes | jq .

# webhook (sign with secret from /hooks/register)
SECRET=$(curl -s -X POST :8080/hooks/register -H "Authorization: Bearer $TOK" | jq -r .secret)
TS=$(date +%s); BODY='{"event":"cap","msg":"ok"}'
SIG=$(python - <<PY
import hmac,hashlib,binascii;sec=binascii.unhexlify("$SECRET");ts="$TS";b=b'$BODY'
print("sha256="+hmac.new(sec,(ts+"\\n").encode()+b,hashlib.sha256).hexdigest())
PY
)
curl -s -X POST :8080/hooks/ingest/amy@example.com -H "X-Timestamp: $TS" -H "X-Signature: $SIG" -H 'content-type: application/json' -d "$BODY" | jq .

# SSRF check
curl -i ':8080/ssrf/fetch?url=http://127.0.0.1:8081/debug/pprof/'


```bash
# GOOD
go run ./cmd/api
# BAD
go run ./cmd/badapi

# JWT + note
TOK=$(curl -s -X POST :8080/auth/login -H 'content-type: application/json' -d '{"email":"amy@example.com","password":"p@ssw0rd"}' | jq -r .token)
curl -s -H "Authorization: Bearer $TOK" -H 'content-type: application/json' -H 'Idempotency-Key: cap-1' -d '{"title":"cap","body":"stone"}' :8080/notes | jq .

# webhook (sign with secret from /hooks/register)
SECRET=$(curl -s -X POST :8080/hooks/register -H "Authorization: Bearer $TOK" | jq -r .secret)
TS=$(date +%s); BODY='{"event":"cap","msg":"ok"}'
SIG=$(python - <<PY
import hmac,hashlib,binascii;sec=binascii.unhexlify("$SECRET");ts="$TS";b=b'$BODY'
print("sha256="+hmac.new(sec,(ts+"\\n").encode()+b,hashlib.sha256).hexdigest())
PY
)
curl -s -X POST :8080/hooks/ingest/amy@example.com -H "X-Timestamp: $TS" -H "X-Signature: $SIG" -H 'content-type: application/json' -d "$BODY" | jq .

# SSRF check
curl -i ':8080/ssrf/fetch?url=http://127.0.0.1:8081/debug/pprof/'

```

#!/usr/bin/env bash
# api_probe.sh — quick API exerciser & safety checks for your Drogon app
# Usage: ./api_probe.sh <BASE_URL> <EMAIL> <PASSWORD>
# Requires: curl, jq
set -Eeuo pipefail

BASE_URL="${1:-}"
EMAIL="${2:-}"
PASSWORD="${3:-}"

if ! command -v curl >/dev/null || ! command -v jq >/dev/null; then
  echo "Please install curl and jq." >&2
  exit 1
fi

if [[ -z "${BASE_URL}" || -z "${EMAIL}" || -z "${PASSWORD}" ]]; then
  echo "Usage: $0 <BASE_URL> <EMAIL> <PASSWORD>" >&2
  exit 1
fi

GREEN='\033[0;32m'; RED='\033[0;31m'; YEL='\033[1;33m'; NC='\033[0m'
ok(){ echo -e "${GREEN}[OK]${NC} $*"; }
warn(){ echo -e "${YEL}[WARN]${NC} $*"; }
fail(){ echo -e "${RED}[FAIL]${NC} $*"; }

JQ() { jq -r "$@" 2>/dev/null || true; }

log_section(){
  echo; echo "============================================"
  echo "$1"
  echo "============================================"
}

# Helper: HTTP request (returns full response incl. headers)
API(){
  local method="$1"; shift
  local path="$1"; shift
  local data="${1:-}"; shift || true
  local -a extra_hdr=("$@")

  if [[ -n "$data" ]]; then
    curl -sS -i -X "$method" "${BASE_URL}${path}" \
      -H "Content-Type: application/json" \
      "${extra_hdr[@]}" \
      --data "$data"
  else
    curl -sS -i -X "$method" "${BASE_URL}${path}" \
      "${extra_hdr[@]}"
  fi
}

# Parse status code from a full HTTP response
status_code_of(){ printf "%s" "$1" | awk 'NR==1{print $2}'; }

expect_status(){
  local want="$1"; shift
  local desc="$1"; shift
  local resp="$1"
  local got; got="$(status_code_of "$resp")"
  if [[ "$got" == "$want" ]]; then ok "HTTP $want as expected for $desc"
  else fail "Expected HTTP $want for $desc, got ${got:-unknown}"
  fi
}

TOKEN=""
register_if_needed(){
  log_section "OPTIONAL: /register"
  local payload; payload="$(jq -n --arg e "$EMAIL" --arg p "$PASSWORD" --arg n "Probe User" '{email:$e,password:$p,name:$n}')"
  local resp; resp="$(API POST /register "$payload")" || true
  local code; code="$(status_code_of "$resp")"
  case "$code" in
    201) ok "Registered new user";;
    409) warn "User already exists (409). Continuing.";;
    *)  warn "Register returned $code; continuing.";;
  esac
}

login(){
  log_section "AUTH: /login"
  local payload; payload="$(jq -n --arg e "$EMAIL" --arg p "$PASSWORD" '{email:$e,password:$p}')"
  local resp; resp="$(API POST /login "$payload")" || true
  expect_status 200 "/login" "$resp"
  TOKEN="$(printf "%s" "$resp" | sed -n '/^\r\{0,1\}$/,$p' | JQ '.token // empty')"
  if [[ -n "$TOKEN" ]]; then ok "Got token (len ${#TOKEN})"; else fail "No token returned"; fi
}

check_security_headers(){
  log_section "HEADERS: security headers on /"
  local hdr; hdr="$(curl -sS -I "${BASE_URL}/")"
  echo "$hdr"
  grep -qi '^x-content-type-options: *nosniff' <<<"$hdr" && ok "X-Content-Type-Options present" || warn "Missing X-Content-Type-Options"
  grep -qi '^x-frame-options:' <<<"$hdr" && ok "X-Frame-Options present" || warn "Missing X-Frame-Options"
  grep -qi '^content-security-policy:' <<<"$hdr" && ok "CSP present" || warn "Missing Content-Security-Policy"
  grep -qi '^referrer-policy:' <<<"$hdr" && ok "Referrer-Policy present" || warn "Missing Referrer-Policy"
  grep -qi '^strict-transport-security:' <<<"$hdr" && ok "HSTS present" || warn "Missing HSTS (HTTPS expected?)"
}

unauthz_checks(){
  log_section "ACCESS CONTROL: unauthenticated"
  local r
  r="$(API GET /users "")"; expect_status 401 "/users (no auth)" "$r"
  r="$(API GET /properties "")"
  if [[ "$(status_code_of "$r")" == "401" ]]; then ok "Properties protected (401)"
  else warn "Properties not 401; check if intended public"; fi
}

basic_crud_properties(){
  log_section "CRUD: properties with auth"
  local auth=(-H "Authorization: Bearer $TOKEN")
  local create='{"landlord_id":77,"name":"Probe House","address":"1 Test Ln","city":"Testville","state":"TS","zip":"00000"}'
  local r id

  r="$(API POST /properties "$create" "${auth[@]}")"; expect_status 201 "POST /properties" "$r"
  id="$(printf "%s" "$r" | sed -n '/^\r\{0,1\}$/,$p' | JQ '.id // empty')"
  [[ -n "$id" ]] && ok "Created property id=$id" || fail "No id from create"

  r="$(API GET "/properties/${id}" "" "${auth[@]}")"; expect_status 200 "GET /properties/{id}" "$r"
  r="$(API PUT "/properties/${id}" '{"name":"Probe House (Updated)"}' "${auth[@]}")"; expect_status 200 "PUT /properties/{id}" "$r"
  r="$(API DELETE "/properties/${id}" "" "${auth[@]}")"; expect_status 200 "DELETE /properties/{id}" "$r"
}

idor_probe(){
  log_section "IDOR: modify other user id"
  local auth=(-H "Authorization: Bearer $TOKEN")
  local target_id=1
  local r; r="$(API PUT "/users/${target_id}" '{"name":"Pwned"}' "${auth[@]}" || true)"
  local code; code="$(status_code_of "$r")"
  case "$code" in
    403) ok "IDOR blocked with 403";;
    404) ok "Not found or access-controlled";;
    401) ok "Unauthorized without scope";;
    200) warn "Potential IDOR: updated user ${target_id}";;
    *)   warn "Unexpected $code on IDOR probe";;
  esac
}

injection_probes(){
  log_section "INPUT VALIDATION: odd IDs & SQL-ish names"
  local auth=(-H "Authorization: Bearer $TOKEN")
  local r code

  r="$(API GET "/users/1%27%20OR%20%271%27=%271" "" "${auth[@]}" || true)"
  code="$(status_code_of "$r")"
  case "$code" in
    400|404) ok "Handled suspicious ID safely ($code)";;
    500)     warn "500 on odd ID; check sanitization/handlers";;
    200)     warn "Returned 200 on suspicious ID; verify validators";;
  esac

  r="$(API POST /users "$(jq -n '{email:"inj@example.com",password:"x",name:"Robert\u0027 OR \u00271\u0027=\u00271 --"}')" "${auth[@]}" || true)"
  code="$(status_code_of "$r")"
  if [[ "$code" == "201" ]]; then warn "SQL-like name accepted (OK if parameterized; review)"
  elif [[ "$code" =~ ^4..$ ]]; then ok "Rejected suspicious payload ($code)"
  else warn "Unexpected code $code for SQL-like payload"
  fi
}

jwt_tamper(){
  log_section "AUTHN: tampered token"
  local bad="${TOKEN/a/b}"
  local r; r="$(API GET /properties "" -H "Authorization: Bearer $bad" || true)"
  local code; code="$(status_code_of "$r")"
  case "$code" in
    401|403) ok "Tampered token rejected ($code)";;
    200)     warn "Tampered token accepted! Investigate JWT validation.";;
    *)       warn "Unexpected $code for tampered token";;
  esac
}

rate_limit_probe(){
  log_section "RATE LIMIT: bursts"
  local ok_count=0
  for _ in $(seq 1 15); do
    local r; r="$(API POST /login "$(jq -n --arg e "$EMAIL" --arg p "$PASSWORD" '{email:$e,password:$p}')" || true)"
    [[ "$(status_code_of "$r")" == "429" ]] && ok_count=$((ok_count+1))
    sleep 0.1
  done
  (( ok_count > 0 )) && ok "Saw $ok_count x 429 on /login" || warn "No 429s on /login; consider rate limits"

  ok_count=0
  for _ in $(seq 1 30); do
    local r; r="$(API GET /properties "" -H "Authorization: Bearer $TOKEN" || true)"
    [[ "$(status_code_of "$r")" == "429" ]] && ok_count=$((ok_count+1))
    sleep 0.05
  done
  (( ok_count > 0 )) && ok "Saw 429s on GET /properties" || warn "No 429s on GET /properties"
}

content_type_probe(){
  log_section "CONTENT-TYPE checks"
  local r code
  r="$(curl -sS -i -X POST "${BASE_URL}/properties" -H "Authorization: Bearer $TOKEN" --data '{"name":"NoHeader"}' || true)"
  code="$(status_code_of "$r")"
  [[ "$code" =~ ^4..$ ]] && ok "Rejected request without Content-Type ($code)" || warn "Accepted request without Content-Type ($code)"

  r="$(curl -sS -i -X POST "${BASE_URL}/properties" -H "Authorization: Bearer $TOKEN" -H "Content-Type: text/plain" --data '{"name":"WrongType"}' || true)"
  code="$(status_code_of "$r")"
  [[ "$code" =~ ^4..$ ]] && ok "Rejected wrong Content-Type ($code)" || warn "Accepted wrong Content-Type ($code)"
}

cors_probe(){
  log_section "CORS: preflight /properties"
  local resp; resp="$(curl -sS -i -X OPTIONS "${BASE_URL}/properties" \
    -H "Origin: https://evil.example" \
    -H "Access-Control-Request-Method: POST" \
    -H "Access-Control-Request-Headers: Authorization, Content-Type" || true)"
  echo "$resp"
  grep -qi '^Access-Control-Allow-Origin:' <<<"$resp" && ok "CORS ACAO present" || warn "No Access-Control-Allow-Origin"
  grep -qi '^Access-Control-Allow-Methods:' <<<"$resp" && ok "CORS methods present" || warn "No Access-Control-Allow-Methods"
}

summary(){
  log_section "DONE"
  echo "Review WARN/FAIL above. Harden: input validation, authZ, rate limiting,"
  echo "security headers, consistent errors, and add audit logs."
}

# ---- Run flow ----
check_security_headers
register_if_needed
login
unauthz_checks
basic_crud_properties
idor_probe
injection_probes
jwt_tamper
rate_limit_probe
content_type_probe
cors_probe
summary


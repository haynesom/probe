#!/usr/bin/env bash
set -e

BASE_URL="https://service.haynesrentmanager.com"
TEST_FILE="baseline_tests.json"
RESULT_FILE="baseline_results.json"

echo "Running baseline tests..."
echo "==========================="
echo "" > "$RESULT_FILE"

# Store JWT here if /login succeeds
AUTH_TOKEN=""

run_test() {
  local name="$1"
  local method="$2"
  local endpoint="$3"
  local body="$4"
  local expected="$5"
  local auth="$6"

  local url="${BASE_URL}${endpoint}"

  # Build curl command
  local cmd=(curl -s -o /tmp/baseline_resp.txt -w "%{http_code}" -X "$method")

  # Include JSON body
  if [ "$body" != "null" ]; then
    cmd+=(-H "Content-Type: application/json" -d "$body")
  fi

  # Include Authorization header if needed
  if [ "$auth" = "true" ] && [ -n "$AUTH_TOKEN" ]; then
    cmd+=(-H "Authorization: Bearer $AUTH_TOKEN")
  fi

  cmd+=("$url")

  # Execute request
  STATUS_CODE=$("${cmd[@]}")
  RESPONSE=$(cat /tmp/baseline_resp.txt)

  # If the test is login and succeeded → extract token
  if [[ "$endpoint" == "/login" && "$STATUS_CODE" == "200" ]]; then
    AUTH_TOKEN=$(echo "$RESPONSE" | jq -r '.token')
    echo "[INFO] Saved JWT token for authenticated requests"
  fi

  # Log results
  jq -n \
    --arg name "$name" \
    --arg method "$method" \
    --arg endpoint "$endpoint" \
    --arg expected "$expected" \
    --arg actual "$STATUS_CODE" \
    --arg response "$RESPONSE" \
    '{
      test_name: $name,
      method: $method,
      endpoint: $endpoint,
      expected_status: ($expected | tonumber),
      actual_status: ($actual | tonumber),
      response_body: $response
    }' >> "$RESULT_FILE"

  # Pretty terminal output
  if [ "$STATUS_CODE" == "$expected" ]; then
    echo "[PASS] $name  ($method $endpoint)"
  else
    echo "[FAIL] $name  ($method $endpoint)"
    echo "       Expected: $expected, Got: $STATUS_CODE"
  fi
}

# Loop through tests in baseline_tests.json
jq -c '.tests[]' "$TEST_FILE" | while read -r t; do
  name=$(echo "$t" | jq -r '.name')
  method=$(echo "$t" | jq -r '.method')
  endpoint=$(echo "$t" | jq -r '.endpoint')
  body=$(echo "$t" | jq -r '.body // null')
  expected=$(echo "$t" | jq -r '.expected_status')
  auth=$(echo "$t" | jq -r '.auth // false')

  run_test "$name" "$method" "$endpoint" "$body" "$expected" "$auth"
done

echo ""
echo "Baseline testing complete. Results saved to $RESULT_FILE"

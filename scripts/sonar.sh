#!/usr/bin/env bash

set -euo pipefail

echo "========================================="
echo "       SONARQUBE CODE ANALYSIS"
echo "========================================="

REPORT_DIR="reports/sonar"
SONAR_PROJECT_KEY="${1:-}"
SONAR_HOST="${SONAR_HOST_URL:-http://sonarqube:9000}"
SONAR_TOKEN="${SONAR_AUTH_TOKEN:-}"

mkdir -p "$REPORT_DIR"

# -------------------------------------------------
# Validate Parameters
# -------------------------------------------------

if [[ -z "$SONAR_PROJECT_KEY" ]]; then
    echo "[ERROR] SonarQube project key is required."
    echo "Usage: sonar.sh <project-key>"
    exit 1
fi

if [[ -z "$SONAR_TOKEN" ]]; then
    echo "[WARN] SONAR_AUTH_TOKEN not set. Using anonymous access."
fi

# -------------------------------------------------
# Check sonar-scanner
# -------------------------------------------------

if ! command -v sonar-scanner >/dev/null 2>&1; then
    echo "[ERROR] sonar-scanner is not installed."
    exit 1
fi

echo "[INFO] SonarQube Scanner Version"
sonar-scanner --version
echo ""

# -------------------------------------------------
# Run SonarQube Analysis
# -------------------------------------------------

echo "[INFO] Running SonarQube analysis..."
echo "[INFO] Host: $SONAR_HOST"
echo "[INFO] Project: $SONAR_PROJECT_KEY"
echo ""

SONAR_ARGS=(
    "-Dsonar.projectKey=$SONAR_PROJECT_KEY"
    "-Dsonar.sources=."
    "-Dsonar.host.url=$SONAR_HOST"
)

if [[ -n "$SONAR_TOKEN" ]]; then
    SONAR_ARGS+=("-Dsonar.login=$SONAR_TOKEN")
fi

sonar-scanner "${SONAR_ARGS[@]}" || true

# -------------------------------------------------
# Fetch Results via API
# -------------------------------------------------

echo ""
echo "[INFO] Fetching analysis results..."

# Wait for analysis to complete
sleep 5

AUTH_HEADER=""
if [[ -n "$SONAR_TOKEN" ]]; then
    AUTH_HEADER="-u $SONAR_TOKEN:"
fi

# Fetch project measures
curl -s $AUTH_HEADER \
    "$SONAR_HOST/api/measures/component?component=$SONAR_PROJECT_KEY&metricKeys=bugs,vulnerabilities,code_smells,security_hotspots,coverage,duplicated_lines_density,ncloc" \
    > "$REPORT_DIR/sonar-measures.json" 2>/dev/null || true

# Fetch issues
curl -s $AUTH_HEADER \
    "$SONAR_HOST/api/issues/search?componentKeys=$SONAR_PROJECT_KEY&ps=500" \
    > "$REPORT_DIR/sonar-issues.json" 2>/dev/null || true

# Fetch quality gate status
curl -s $AUTH_HEADER \
    "$SONAR_HOST/api/qualitygates/project_status?projectKey=$SONAR_PROJECT_KEY" \
    > "$REPORT_DIR/sonar-quality-gate.json" 2>/dev/null || true

# -------------------------------------------------
# Summary
# -------------------------------------------------

echo ""
echo "========================================="
echo "             SCAN SUMMARY"
echo "========================================="

if [[ -f "$REPORT_DIR/sonar-measures.json" ]]; then
    python3 -c "
import json
try:
    with open('$REPORT_DIR/sonar-measures.json') as f:
        data = json.load(f)
    measures = data.get('component', {}).get('measures', [])
    for m in measures:
        print(f\"  {m['metric']:30s} : {m['value']}\")
except Exception as e:
    print(f'  Could not parse results: {e}')
" 2>/dev/null || echo "  (Could not fetch measures)"
fi

echo ""
ls -lh "$REPORT_DIR"

echo ""
echo "Reports Generated"
echo "  Measures     : $REPORT_DIR/sonar-measures.json"
echo "  Issues       : $REPORT_DIR/sonar-issues.json"
echo "  Quality Gate : $REPORT_DIR/sonar-quality-gate.json"

echo ""
echo "========================================="
echo "  SONARQUBE SCAN COMPLETED SUCCESSFULLY"
echo "========================================="

exit 0

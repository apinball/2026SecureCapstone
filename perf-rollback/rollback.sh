#!/bin/bash
# rollback.sh — Performance-gate rollback handler
# Usage: rollback.sh <stage> <summary_file>
# Runs on the pipeline runner (host); reads perf-check-summary.json and
# rolls back to the previous stage nginx.conf if result is "fail".

set -euo pipefail

STAGE_ARG="${1:-}"
SUMMARY_FILE="${2:-}"

if [ -z "$STAGE_ARG" ] || [ -z "$SUMMARY_FILE" ]; then
    echo "Usage: rollback.sh <stage> <summary_file>"
    echo "  stage: 1, 2, or 3"
    exit 1
fi

STAGE=$(echo "$STAGE_ARG" | tr -d '[:space:]')

if [ ! -f "$SUMMARY_FILE" ]; then
    echo "[ERROR] Summary file not found: $SUMMARY_FILE"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
mkdir -p "$RESULTS_DIR"
ROLLBACK_SUMMARY="$RESULTS_DIR/rollback-summary.json"

echo "=== Rollback Check ==="
echo "Stage       : $STAGE"
echo "Summary file: $SUMMARY_FILE"
echo ""

# Parse result and fail_reason from perf-check-summary.json
PERF_RESULT=$(python3 -c "
import json, sys
with open('$SUMMARY_FILE') as f:
    d = json.load(f)
print(d.get('result', 'unknown'))
")

FAIL_REASON=$(python3 -c "
import json, sys
with open('$SUMMARY_FILE') as f:
    d = json.load(f)
print(d.get('fail_reason', ''))
")

# No rollback needed if result is not "fail"
if [ "$PERF_RESULT" != "fail" ]; then
    echo "[SKIP] No rollback needed (result: $PERF_RESULT)"

    python3 -c "
import json
summary = {
    'tool': 'rollback',
    'result': 'skipped',
    'stage_from': $STAGE,
    'stage_to': None,
    'fail_reason': '$FAIL_REASON',
    'commit_message': ''
}
with open('$ROLLBACK_SUMMARY', 'w') as f:
    json.dump(summary, f, indent=2)
"
    exit 0
fi

# Stage 1 is not a rollback target
if [ "$STAGE" -eq 1 ]; then
    echo "[SKIP] Stage 1 is not a rollback target"

    python3 -c "
import json
summary = {
    'tool': 'rollback',
    'result': 'skipped',
    'stage_from': 1,
    'stage_to': None,
    'fail_reason': '$FAIL_REASON',
    'commit_message': ''
}
with open('$ROLLBACK_SUMMARY', 'w') as f:
    json.dump(summary, f, indent=2)
"
    exit 0
fi

# Determine rollback source conf and target stage
case "$STAGE" in
    2)
        STAGE_TO=1
        SRC_CONF="nginx/nginx-ecc.conf"
        ;;
    3)
        STAGE_TO=2
        SRC_CONF="nginx/nginx-hybrid.conf"
        ;;
    *)
        echo "[ERROR] Unsupported stage for rollback: $STAGE"
        exit 1
        ;;
esac

COMMIT_MSG="Auto-rollback: Stage ${STAGE} → Stage ${STAGE_TO} due to performance degradation [skip ci]"

echo "[ROLLBACK] Stage ${STAGE} → Stage ${STAGE_TO}"
echo "  Source conf : $SRC_CONF"
echo "  Commit msg  : $COMMIT_MSG"
echo ""

# Verify source conf exists
if [ ! -f "$SRC_CONF" ]; then
    echo "[ERROR] Rollback source not found: $SRC_CONF"
    exit 1
fi

# Copy previous stage conf to nginx.conf
cp "$SRC_CONF" nginx/nginx.conf

# Configure git identity for the bot commit
git config user.name "PQC Rollback Bot"
git config user.email "pqc-rollback-bot@github-actions.com"

git add nginx/nginx.conf

# Guard against empty commit when nginx.conf is already identical to the rollback target
if git diff --cached --quiet; then
    echo "[INFO] nginx.conf already matches rollback target — nothing to commit"

    python3 -c "
import json
summary = {
    'tool': 'rollback',
    'result': 'skipped',
    'stage_from': $STAGE,
    'stage_to': $STAGE_TO,
    'fail_reason': '''$FAIL_REASON''',
    'commit_message': ''
}
with open('$ROLLBACK_SUMMARY', 'w') as f:
    json.dump(summary, f, indent=2)
"
    exit 0
fi

# Create a dedicated rollback branch to avoid direct push to protected develop
ROLLBACK_BRANCH="rollback/stage-${STAGE}-to-${STAGE_TO}-$(date +%Y%m%d%H%M%S)"
git checkout -b "$ROLLBACK_BRANCH"
git commit -m "$COMMIT_MSG"
git push origin "$ROLLBACK_BRANCH"

echo ""
echo "Rollback branch pushed: $ROLLBACK_BRANCH"

# Open a PR targeting develop so branch protection rules are satisfied
PR_TITLE="Auto-rollback: Stage ${STAGE} → Stage ${STAGE_TO} due to performance degradation"
PR_BODY="## Auto-rollback triggered

**Fail reason:** ${FAIL_REASON}

This PR was automatically created by the perf-rollback pipeline step.
Merging this PR will revert nginx.conf to the Stage ${STAGE_TO} configuration."

PR_URL=$(gh pr create \
    --base develop \
    --head "$ROLLBACK_BRANCH" \
    --title "$PR_TITLE" \
    --body "$PR_BODY" 2>&1) || PR_URL="pr-create-failed"

echo "PR created: $PR_URL"

# Write rollback summary JSON including branch and PR URL
python3 -c "
import json
summary = {
    'tool': 'rollback',
    'result': 'executed',
    'stage_from': $STAGE,
    'stage_to': $STAGE_TO,
    'fail_reason': '''$FAIL_REASON''',
    'commit_message': '''$COMMIT_MSG''',
    'branch_name': '$ROLLBACK_BRANCH',
    'pr_url': '$PR_URL'
}
with open('$ROLLBACK_SUMMARY', 'w') as f:
    json.dump(summary, f, indent=2)
"

exit 0

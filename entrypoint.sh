#!/bin/bash
set -euo pipefail

# Mark the workspace as safe for git operations inside the container
git config --global --add safe.directory /github/workspace

# Build guardian flags
FLAGS="--full --no-color"

if [ "${INPUT_SCAN_OSV}" = "false" ]; then
  FLAGS="${FLAGS} --no-osv"
fi

if [ "${INPUT_SCAN_SECRETS}" = "false" ]; then
  FLAGS="${FLAGS} --no-secrets"
fi

if [ "${INPUT_SCAN_SAST}" = "false" ]; then
  FLAGS="${FLAGS} --no-sast"
fi

echo "::group::Guardian Security Scan"
# shellcheck disable=SC2086
guardian check ${FLAGS}
EXIT_CODE=$?
echo "::endgroup::"

if [ "${INPUT_FAIL_ON_FINDINGS}" = "false" ]; then
  exit 0
fi

exit ${EXIT_CODE}

#!/usr/bin/env bash
# Loop over every scenario YAML matching $SCENARIOS_GLOB. For each:
#   - run `helios inspect` and dump JSON to $ARTIFACT_DIR/<stem>.json
#   - if $FIXES_DIR/<stem>.json exists, run `helios verify` (against every
#     scenario in the glob) and capture its report into
#     $ARTIFACT_DIR/<stem>.verify.txt -- ADVISORY output only
#
# The gate judges the REAL plan only. A scenario FAILS when its chain has
# failures, or when it is INCONCLUSIVE (helios exits 3: it cannot be evaluated,
# e.g. an iam-revocation on a plan whose roles are unknown; the message goes to
# $ARTIFACT_DIR/<stem>.inconclusive.txt, never read as a pass). A fix file never
# passes a scenario: `verify` edits Helios's in-memory graph, not the Terraform,
# so a PR whose Terraform is unchanged would pass. Failed stems are written one
# per line to $GATE_FILE (empty file = all passed); the action's last step gates on it.
#
# Inputs (env): HELIOS_BIN, SCENARIOS_GLOB, FIXES_DIR, TERRAFORM_JSON, ARTIFACT_DIR, GATE_FILE
# Output (GHA step): artifact-dir = $ARTIFACT_DIR
set -euo pipefail

# Fresh each run: a second invocation in the same job must not report the first one's scenarios.
rm -rf "$ARTIFACT_DIR"
mkdir -p "$ARTIFACT_DIR"
: > "$GATE_FILE"

# Expand the glob portably. Globbing inside `for` requires no quotes.
shopt -s nullglob
matches=( $SCENARIOS_GLOB )
shopt -u nullglob

if [[ ${#matches[@]} -eq 0 ]]; then
  echo "::error::no scenarios matched glob '$SCENARIOS_GLOB'"
  exit 1
fi

for scenario in "${matches[@]}"; do
  stem="$(basename "$scenario" .yaml)"
  echo "::group::scenario $stem"

  inspect_out="$ARTIFACT_DIR/$stem.json"
  set +e
  "$HELIOS_BIN" inspect "$TERRAFORM_JSON" --scenario "$scenario" > "$inspect_out" \
    2> "$ARTIFACT_DIR/$stem.stderr.txt"
  rc=$?
  set -e
  cat "$ARTIFACT_DIR/$stem.stderr.txt" >&2
  if [[ $rc -eq 3 ]]; then
    rm -f "$inspect_out"
    # Only helios's verdict line: graph-build warnings also say INCONCLUSIVE.
    grep -h '^helios: INCONCLUSIVE' "$ARTIFACT_DIR/$stem.stderr.txt" > "$ARTIFACT_DIR/$stem.inconclusive.txt" || true
    rm -f "$ARTIFACT_DIR/$stem.stderr.txt"
    echo "::warning::helios: $stem is INCONCLUSIVE (not a pass)"
    echo "$stem" >> "$GATE_FILE"
    echo "::endgroup::"
    continue
  fi
  rm -f "$ARTIFACT_DIR/$stem.stderr.txt"
  if [[ $rc -ne 0 ]]; then
    echo "::error::helios inspect failed for $stem"
    exit 1
  fi
  echo "wrote $inspect_out ($(wc -c < "$inspect_out") bytes)"

  # A standalone assignment, so `set -e` aborts if jq is missing rather than the gate silently passing.
  failure_count=$(jq '.chain.failures | length' "$inspect_out")

  if [[ $failure_count -gt 0 ]]; then
    echo "$stem" >> "$GATE_FILE"
  fi

  fix_path="$FIXES_DIR/$stem.json"
  if [[ -f "$fix_path" ]]; then
    verify_out="$ARTIFACT_DIR/$stem.verify.txt"
    # Advisory: what the fix WOULD do if made in the Terraform. Its exit code never touches the gate.
    scenario_args=()
    for s in "${matches[@]}"; do scenario_args+=(--scenario "$s"); done
    set +e
    "$HELIOS_BIN" verify "$TERRAFORM_JSON" "${scenario_args[@]}" --fix "$fix_path" \
      > "$verify_out" 2>&1
    rc=$?
    set -e
    echo "wrote $verify_out (advisory verify rc=$rc; the gate judges the plan only)"
  fi

  echo "::endgroup::"
done

echo "artifact-dir=$ARTIFACT_DIR" >> "$GITHUB_OUTPUT"

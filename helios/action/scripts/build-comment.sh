#!/usr/bin/env bash
# Aggregate $ARTIFACT_DIR/*.json + $ARTIFACT_DIR/*.verify.txt into a single
# sticky-comment markdown body at $COMMENT_PATH.
#
# The marker `<!-- helios-action -->` in the body lets post-sticky.sh upsert
# instead of duplicating on each run.
#
# Inputs (env): ARTIFACT_DIR, COMMENT_PATH, ARTIFACT_NAME, RUN_ID, SERVER_URL, REPOSITORY
# Output (GHA step): body-path = $COMMENT_PATH
set -euo pipefail

# Scenario names, stems, resource ids, kinds and reasons come from the PR (its plan, its scenario
# files), so none goes into the comment raw. `html`: for HTML contexts (<summary>, <pre>). `md`: for
# markdown text and table cells -- also one line, and markdown's specials (| ` * _ [ ] ...) escaped.
JQ_ESC='def html: tostring | gsub("&"; "&amp;") | gsub("<"; "&lt;") | gsub(">"; "&gt;");
def md: html | gsub("[\r\n]+"; " ") | gsub("(?<c>[\\\\`*_{}\\[\\]()#+!|~])"; "\\\(.c)");'
html() { jq -rn --arg s "$1" "$JQ_ESC"' $s | html'; }
# A captured text file as a <pre> block: no ``` fence for its content to close.
pre() { echo "<pre>"; jq -Rr "$JQ_ESC"' html' "$1"; echo "</pre>"; }

artifact_url="$SERVER_URL/$REPOSITORY/actions/runs/$RUN_ID#artifacts"

{
  echo "<!-- helios-action -->"
  echo "## Helios PR analysis"
  echo
  echo "Ran \`helios inspect\` over $(ls "$ARTIFACT_DIR"/*.json "$ARTIFACT_DIR"/*.inconclusive.txt 2>/dev/null | wc -l | tr -d ' ') scenario(s)."
  echo "Inspect JSON artifacts: [\`$ARTIFACT_NAME\`]($artifact_url) (download and drop into the [web viewer](../../tree/main/web))."
  echo
} > "$COMMENT_PATH"

shopt -s nullglob
# Every inspect JSON is of the same input: the first one says what was NOT simulated.
inspects=( "$ARTIFACT_DIR"/*.json )
if [[ ${#inspects[@]} -gt 0 ]]; then
  skipped=$(jq '[.skipped[]?.count] | add // 0' "${inspects[0]}")
  if [[ "$skipped" -gt 0 ]]; then
    {
      echo "> ⚠️ **$skipped resource(s) of unsupported types were NOT simulated** — absent from the graph, not assumed healthy:"
      echo "> $(jq -r "$JQ_ESC"' [.skipped[] | "\(.type | md) (\(.count))"] | join(", ")' "${inspects[0]}")"
      echo
    } >> "$COMMENT_PATH"
  fi
fi
for inspect_json in "$ARTIFACT_DIR"/*.json; do
  stem="$(basename "$inspect_json" .json)"
  stem_html="$(html "$stem")"
  failure_count=$(jq '.chain.failures | length' "$inspect_json")
  scenario_label=$(jq -r "$JQ_ESC"' .chain.scenario | html' "$inspect_json")

  {
    echo "<details>"
    if [[ "$failure_count" -eq 0 ]]; then
      echo "<summary><strong>$stem_html</strong> — ✅ no failures (<code>$scenario_label</code>)</summary>"
    else
      echo "<summary><strong>$stem_html</strong> — ❌ $failure_count failure(s) (<code>$scenario_label</code>)</summary>"
    fi
    echo
    if [[ "$failure_count" -gt 0 ]]; then
      echo
      echo "| Resource | Kind | Reason |"
      echo "|---|---|---|"
      jq -r "$JQ_ESC"' .chain.failures[:3][] | "| \(.id | md) | \(.kind | md) | \(.reason | md) |"' "$inspect_json"
      if [[ "$failure_count" -gt 3 ]]; then
        echo
        echo "_…and $((failure_count - 3)) more in the artifact._"
      fi
    fi

    verify_txt="$ARTIFACT_DIR/$stem.verify.txt"
    if [[ -f "$verify_txt" ]]; then
      echo
      echo "<p><strong>Advisory — proposed fix <code>fixes/$stem_html.json</code> re-simulated in memory.</strong> It does not change your Terraform and never passes this scenario: make the change in the Terraform and the next run judges the real plan.</p>"
      echo
      pre "$verify_txt"
    fi
    echo
    echo "</details>"
    echo
  } >> "$COMMENT_PATH"
done
for inconclusive in "$ARTIFACT_DIR"/*.inconclusive.txt; do
  stem="$(basename "$inconclusive" .inconclusive.txt)"
  {
    echo "<details open>"
    echo "<summary><strong>$(html "$stem")</strong> — ⚠️ inconclusive: Helios cannot evaluate this scenario (not a pass)</summary>"
    echo
    pre "$inconclusive"
    echo
    echo "</details>"
    echo
  } >> "$COMMENT_PATH"
done
shopt -u nullglob

echo "body-path=$COMMENT_PATH" >> "$GITHUB_OUTPUT"
echo "comment body $(wc -c < "$COMMENT_PATH") bytes:"
cat "$COMMENT_PATH"

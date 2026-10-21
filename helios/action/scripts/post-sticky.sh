#!/usr/bin/env bash
# Upsert a single PR comment carrying the marker `<!-- helios-action -->`.
#
# Lists existing PR comments via `gh api`, finds one with the marker, PATCHes
# it if present, otherwise POSTs a new one. Idempotent across pushes.
#
# Inputs (env): GH_TOKEN, REPOSITORY, PR_NUMBER, COMMENT_PATH
set -euo pipefail

marker='<!-- helios-action -->'

# `gh api` paginates with --paginate. The marker check uses `select(...)` rather
# than grep to avoid quoting escapes biting us.
existing_id=$(gh api --paginate "repos/$REPOSITORY/issues/$PR_NUMBER/comments" \
  --jq "[.[] | select(.body | startswith(\"$marker\"))][0].id // empty")

if [[ -n "$existing_id" ]]; then
  echo "Updating existing comment $existing_id"
  gh api --method PATCH "repos/$REPOSITORY/issues/comments/$existing_id" \
    --field "body=@$COMMENT_PATH" > /dev/null
else
  echo "Creating new comment"
  gh api --method POST "repos/$REPOSITORY/issues/$PR_NUMBER/comments" \
    --field "body=@$COMMENT_PATH" > /dev/null
fi

#!/usr/bin/env bash
#
# Run WARDEN against a REAL AWS account and leave an evidence bundle behind.
#
#   bash scripts/aws_proof.sh
#
# It stands up terraform/proving-ground/, stages five situations against it, records what WARDEN
# said about each, and tears everything down. Roughly 45 minutes end to end and roughly $0.25, most
# of both being EKS.
#
# ------------------------------------------------------------------------------------------------
# WHAT IT PROVES, and why each one is worth the money
#
#   A  ECS, healthy            real task counts and real CloudWatch utilisation, not fixtures
#   B  ECS, force-new-deploy   ⭐ WARDEN reports NO DEPLOY. A restart is not a deploy, so policy P5
#                              is not handed evidence for a rollback that could not possibly help.
#                              This is the one an interviewer should push on: it is the difference
#                              between reading a timestamp and reading the task definition.
#   C  ECS, real bad deploy    a genuine image change plus genuine OOM kills produced by Fargate -
#                              the rollback is both proposed and permitted
#   D  EKS                     the existing k8s backend on MANAGED EKS, not k3d. The README said in
#                              plain words this had never been done; this is what closes it
#   E  RDS                     the existing postgres backend against a real RDS instance
#
# ------------------------------------------------------------------------------------------------
# ⛔ TEARDOWN IS NOT OPTIONAL. An EKS control plane is $0.10/hour whether or not anything runs on
# it. `terraform destroy` runs from an EXIT trap, so it happens even if the proof fails, even on
# Ctrl-C. If it still fails, the script prints the tag query that finds the leftovers and exits
# non-zero. Set KEEP=1 to skip teardown deliberately - it warns loudly.

set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_DIR="$HERE/terraform/proving-ground"
STAMP="$(date -u +%Y-%m-%dT%H%M%SZ)"
# ⛔ OUTSIDE the repository, deliberately.
#
# Redaction happens at the END of a run. A run that aborts - failed apply, Ctrl-C, expired
# credentials - would otherwise leave a raw transcript full of real ARNs (and so the real account
# id) inside the git working tree, waiting for the next `git add -A`. Nothing enters the repo until
# it has been redacted AND scanned.
RUNS_ROOT="${WARDEN_PROOF_DIR:-$HOME/warden-proof-runs}"
OUT="$RUNS_ROOT/aws-proof-$STAMP"
KEEP="${KEEP:-0}"
PY="${PY:-python}"

mkdir -p "$OUT/reports"

log()  { printf '\n\033[1m== %s\033[0m\n' "$*" | tee -a "$OUT/run.log"; }
note() { printf '   %s\n' "$*" | tee -a "$OUT/run.log"; }
die()  { printf '\n\033[31mFAILED: %s\033[0m\n' "$*" | tee -a "$OUT/run.log" >&2; exit 1; }

# --------------------------------------------------------------------------- preflight

log "Preflight"
for tool in aws terraform kubectl "$PY"; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is not installed or not on PATH"
done
aws sts get-caller-identity >/dev/null 2>&1 || die "no working AWS credentials (try: aws configure)"

# The extras must be present BEFORE fifteen minutes of EKS, not after. Each backend imports its
# client lazily, so a missing extra surfaces only when that situation runs.
"$PY" -c "import warden, boto3, kubernetes, psycopg" 2>/dev/null   || die "install the extras first:  pip install -e '.[aws,k8s,postgres]'"

ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
note "account $ACCOUNT"
note "evidence -> $OUT"

[ -f "$TF_DIR/terraform.tfvars" ] || die "create $TF_DIR/terraform.tfvars first (see terraform.tfvars.example)"

# A per-run password. Never written to a tfvars file: a real credential must not outlive the
# environment it belongs to.
DB_PASSWORD="$("$PY" -c 'import secrets,string; a=string.ascii_letters+string.digits; print("".join(secrets.choice(a) for _ in range(24)))')"

# --------------------------------------------------------------------------- teardown trap

destroyed=0
teardown() {
  local rc=$?
  [ "$destroyed" = "1" ] && return $rc
  destroyed=1
  if [ "$KEEP" = "1" ]; then
    printf '\n\033[31m⛔ KEEP=1 — the environment is STILL RUNNING and still billing.\033[0m\n'
    printf '   Destroy it with:  terraform -chdir=%s destroy -var db_password=<the one it was created with>\n' "$TF_DIR"
    return $rc
  fi
  log "Teardown"
  if terraform -chdir="$TF_DIR" destroy -auto-approve -var "db_password=$DB_PASSWORD" 2>&1 | tee -a "$OUT/run.log"; then
    note "destroy completed"
  else
    printf '\n\033[31m⛔ DESTROY FAILED. The environment is STILL BILLING.\033[0m\n'
    printf '   Find what is left:\n   aws resourcegroupstaggingapi get-resources --tag-filters Key=Project,Values=warden-proving-ground\n'
    return 1
  fi
  # Trust the query, not the exit code: a destroy can report success and leave a node group behind.
  local left
  left="$(aws resourcegroupstaggingapi get-resources \
            --tag-filters Key=Project,Values=warden-proving-ground \
            --query 'length(ResourceTagMappingList)' --output text 2>/dev/null || echo unknown)"
  note "resources still tagged warden-proving-ground: $left"
  echo "$left" > "$OUT/teardown-remaining.txt"
  [ "$left" = "0" ] || printf '\033[31m   ⛔ not zero — check the console before you sleep\033[0m\n'
  return $rc
}
trap teardown EXIT

# --------------------------------------------------------------------------- apply

# ⭐ RDS and EKS default to OFF. Wave 1 needs neither, and the dominant cost risk in this whole
# exercise is not the hourly rate - it is forgetting to destroy something. An idle EKS control plane
# is ~$73/month. Turn one on for the wave that needs it, in terraform.tfvars, and only then.
log "Apply"
terraform -chdir="$TF_DIR" init -input=false >/dev/null 2>&1 || true
terraform -chdir="$TF_DIR" init -input=false            2>&1 | tee -a "$OUT/run.log"
terraform -chdir="$TF_DIR" apply -auto-approve -input=false \
  -var "db_password=$DB_PASSWORD"                       2>&1 | tee -a "$OUT/run.log"

tfout() { terraform -chdir="$TF_DIR" output -raw "$1"; }
REGION="$(tfout region)"
CLUSTER="$(tfout ecs_cluster)"
SERVICE="$(tfout ecs_service)"
LOG_GROUP="$(tfout log_group)"
BAD_TASKDEF="$(tfout task_definition_bad)"
EKS_CLUSTER="$(tfout eks_cluster)"

export AWS_REGION="$REGION"
export WARDEN_BACKEND=aws
export WARDEN_AWS_CLUSTER="$CLUSTER"
export WARDEN_AWS_LOG_GROUP="$LOG_GROUP"
# A live account is slower than a fixture read; the default 5s budget will time a tool out.
export WARDEN_TOOL_TIMEOUT="${WARDEN_TOOL_TIMEOUT:-15}"

warden_run() {  # warden_run <situation> <note> [extra args...]
  local tag="$1" desc="$2"; shift 2
  log "$tag — $desc"
  "$PY" -m warden.cli run \
      --incident inc-002 --started-at now --service "$SERVICE" \
      --label "cluster=$CLUSTER" --label "log_group=$LOG_GROUP" \
      --json "$OUT/reports/$tag.json" --verbose "$@" 2>&1 | tee -a "$OUT/run.log"
}

wait_steady() {
  note "waiting for the service to settle"
  aws ecs wait services-stable --cluster "$CLUSTER" --services "$SERVICE" || true
}

# --------------------------------------------------------------------------- A: healthy

wait_steady
note "letting CloudWatch publish a datapoint (ECS service metrics are 1-minute)"
sleep 120
warden_run A-ecs-healthy "ECS healthy — real task counts, real CloudWatch metrics"

# --------------------------------------------------------------------------- B: the honest one

log "B — forcing a NEW DEPLOYMENT with the SAME task definition"
note "this is ECS's 'kubectl rollout restart'. WARDEN must NOT call it a deploy."
aws ecs update-service --cluster "$CLUSTER" --service "$SERVICE" --force-new-deployment >/dev/null
wait_steady
warden_run B-ecs-force-new-deployment "ECS restart — must report NO deploy"

if "$PY" -c "
import json,sys
d=json.load(open(r'$OUT/reports/B-ecs-force-new-deployment.json'))
sys.exit(0 if not d['context']['recent_deploys'] else 1)
"; then
  note "✅ no deploy reported — a restart was correctly not read as a template change"
  echo pass > "$OUT/reports/B-verdict.txt"
else
  note "⛔ a deploy WAS reported for a restart. That is the defect this design exists to prevent."
  echo fail > "$OUT/reports/B-verdict.txt"
fi

# --------------------------------------------------------------------------- C: a real bad deploy

log "C — deploying the OOM revision (a REAL image change)"
aws ecs update-service --cluster "$CLUSTER" --service "$SERVICE" \
    --task-definition "$BAD_TASKDEF" >/dev/null
note "waiting for Fargate to actually kill the tasks"
sleep 240   # not services-stable: it never stabilises, which is the point
aws ecs describe-services --cluster "$CLUSTER" --services "$SERVICE" \
    --query 'services[0].{running:runningCount,desired:desiredCount,pending:pendingCount}' \
    --output table | tee -a "$OUT/run.log"
warden_run C-ecs-bad-deploy "ECS bad deploy — real OOM kills, rollback should be permitted" \
    --principal role:oncall --report

# --------------------------------------------------------------------------- D: EKS

if [ -n "$EKS_CLUSTER" ]; then
  log "D — EKS (managed Kubernetes, not k3d)"
  aws eks update-kubeconfig --region "$REGION" --name "$EKS_CLUSTER" 2>&1 | tee -a "$OUT/run.log"
  kubectl wait --for=condition=Ready node --all --timeout=300s 2>&1 | tee -a "$OUT/run.log"
  kubectl get nodes -o wide 2>&1 | tee -a "$OUT/reports/D-eks-nodes.txt"

  kubectl apply -k "$HERE/k8s/"                              2>&1 | tee -a "$OUT/run.log"
  kubectl apply -f "$HERE/k8s/test/oom-workload.yaml"        2>&1 | tee -a "$OUT/run.log"

  # The same negative check CI runs on k3d, now on a cluster that enforces Pod Security for real.
  if kubectl apply --dry-run=server -f "$HERE/k8s/test/privileged-must-fail.yaml" 2>"$OUT/reports/D-privileged-rejected.txt"; then
    note "⛔ EKS ACCEPTED a privileged pod — Pod Security is not enforced on this namespace"
  else
    note "✅ EKS rejected the privileged pod"
  fi

  note "letting the workload OOM"
  sleep 90
  kubectl get pods -o wide 2>&1 | tee -a "$OUT/reports/D-eks-pods.txt"

  WARDEN_BACKEND=k8s WARDEN_K8S_NAMESPACE=default \
    "$PY" -m warden.cli run --incident inc-002 --started-at now \
      --json "$OUT/reports/D-eks.json" --verbose 2>&1 | tee -a "$OUT/run.log"
else
  note "EKS disabled (enable_eks=false) — situation D skipped"
fi

# --------------------------------------------------------------------------- E: RDS

DSN="$(terraform -chdir="$TF_DIR" output -raw db_dsn 2>/dev/null || true)"
if [ -n "$DSN" ]; then
  log "E — RDS PostgreSQL"
  # ⛔ The DSN carries the master password. It is scrubbed out of the transcript on the way past,
  # and aws_proof_bundle.py scrubs the whole bundle again afterwards. Two passes, because this is
  # the one value in the run that must never reach a published file.
  WARDEN_BACKEND=postgres WARDEN_DB_DSN="$DSN" \
    "$PY" -m warden.cli run --incident inc-005 --started-at now \
      --json "$OUT/reports/E-rds.json" --verbose 2>&1 \
    | sed "s#$DB_PASSWORD#********#g" | tee -a "$OUT/run.log"
else
  note "RDS disabled (enable_rds=false) — situation E skipped. Wave 1 does not need a database, and"
  note "an instance that exists during an ECS-only run is cost plus a month-sized tail risk."
fi

# --------------------------------------------------------------------------- the bundle

log "Writing the evidence bundle"
"$PY" "$HERE/scripts/aws_proof_bundle.py" \
    --dir "$OUT" --account "$ACCOUNT" --region "$REGION" \
    --cluster "$CLUSTER" --service "$SERVICE" --eks "$EKS_CLUSTER" 2>&1 | tee -a "$OUT/run.log"

# The password reached the log through terraform's own output in a few places. Scrub before the
# bundle is shown to anyone. Belt and braces: it should never have been echoed at all.
if [ -f "$OUT/run.log" ]; then
  "$PY" - "$OUT/run.log" "$DB_PASSWORD" <<'PY'
import pathlib, sys
path, secret = pathlib.Path(sys.argv[1]), sys.argv[2]
text = path.read_text(encoding="utf-8", errors="replace")
path.write_text(text.replace(secret, "********"), encoding="utf-8")
PY
fi

# --------------------------------------------------------------------------- publish gate

log "Checking the bundle is safe to publish"

# The bundle has been redacted. Now VERIFY that, independently, before anything enters the git
# working tree - because "the redactor ran" and "the redactor worked" are different claims, and only
# the second one matters.
if "$PY" "$HERE/scripts/check_publishable.py" --dir "$OUT" 2>&1 | tee -a "$OUT/run.log"; then
  DEST="$HERE/docs/aws-proof-$STAMP"
  mkdir -p "$DEST"
  cp -r "$OUT/." "$DEST/"
  note "bundle copied into the repo: $DEST"
  note "it passed the publishability scan, so it is safe to commit"
else
  printf '\n\033[31m!! THE BUNDLE DID NOT PASS THE PUBLISHABILITY SCAN.\033[0m\n'
  printf '   It has been LEFT OUTSIDE the repository at:\n     %s\n' "$OUT"
  printf '   Fix the findings above before copying anything in. Do not commit it.\n'
fi

log "Done"
note "evidence bundle: $OUT"
note "read $OUT/PROOF.md"

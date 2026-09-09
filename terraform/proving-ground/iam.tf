# The role WARDEN actually runs as during the benchmark.
#
# ⛔ THIS FIXES A HOLE THAT WOULD HAVE INVALIDATED A PUBLISHED CLAIM.
#
# Without this file the benchmark runner would invoke WARDEN with whatever credentials the operator
# happens to hold — in practice, admin. Two things would then have been false:
#
#   1. "WARDEN is read-only" would have been an assertion about its *code*, not about what it could
#      actually do. The IAM-vs-code parity test proves the policy matches the calls; it proves
#      nothing at all if the process never runs under that policy.
#   2. Scenario `ecs-11` removes a permission and expects WARDEN to hit AccessDenied. Under admin
#      credentials that scenario silently measures nothing, and would have been published as a pass.
#
# So the runner assumes THIS role — four read actions, nothing else — and every scenario is answered
# by a process that genuinely cannot do anything but read. That is a checkable claim rather than a
# design intention, and `scenarios/runner.py` records the assumed-role ARN in the evidence bundle.

data "aws_iam_policy_document" "reader_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type = "AWS"
      # Any principal in this account that is itself permitted to assume it. Scoping to the caller's
      # exact ARN breaks the moment the benchmark runs from GitHub Actions under an OIDC role
      # instead of from a laptop, and a trust policy that has to be edited per run is a trust policy
      # people widen.
      identifiers = [data.aws_caller_identity.current.account_id]
    }
  }
}

data "aws_iam_policy_document" "reader" {
  statement {
    sid    = "ReadObservabilitySignals"
    effect = "Allow"

    # ⭐ EXACTLY the four calls src/warden/aws_backend.py makes, and the same four the deployment
    # module one directory up grants. tests/test_aws_backend.py asserts set equality against that
    # module in both directions, so this list cannot silently drift from the code either.
    actions = [
      "cloudwatch:GetMetricData",
      "ecs:DescribeServices",
      "ecs:DescribeTaskDefinition",
      "logs:FilterLogEvents",
    ]

    resources = ["*"]
  }
}

resource "aws_iam_role" "reader" {
  # The `warden-` prefix is load-bearing: scenarios/ops.py refuses to modify any role whose name
  # does not start with it, which is what stops a fault injection reaching a real role.
  name                 = "${local.name}-reader"
  assume_role_policy   = data.aws_iam_policy_document.reader_assume.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "reader" {
  name   = "warden-readonly"
  role   = aws_iam_role.reader.id
  policy = data.aws_iam_policy_document.reader.json
}

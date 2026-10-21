"""Dev is run as production (owner, 2026-10-16): its data can be restored. Every DynamoDB table the dev stack and the
runtime module make has point-in-time recovery on; WARDEN's own audit database keeps backups and cannot be deleted
by accident."""

from __future__ import annotations

import fnmatch
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
STACKS = (ROOT / "terraform" / "fullstack", ROOT / "terraform" / "modules" / "warden-runtime")

# Every AWS Backup action (AWS Service Reference, servicereference.us-east-1.amazonaws.com/v1/backup/backup.json,
# read 2026-10-21): the boundary's backup patterns are checked against all of them, not against examples.
BACKUP_ACTIONS = frozenset([
    "AssociateBackupVaultMpaApprovalTeam", "CancelLegalHold", "CopyFromBackupVault", "CopyIntoBackupVault",
    "CreateBackupAccessPoint", "CreateBackupPlan", "CreateBackupSelection", "CreateBackupVault", "CreateFramework",
    "CreateLegalHold", "CreateLogicallyAirGappedBackupVault", "CreateReportPlan", "CreateRestoreAccessBackupVault",
    "CreateRestoreTestingPlan", "CreateRestoreTestingSelection", "CreateTieringConfiguration",
    "DeleteBackupAccessPoint", "DeleteBackupPlan", "DeleteBackupSelection", "DeleteBackupVault",
    "DeleteBackupVaultAccessPolicy", "DeleteBackupVaultLockConfiguration", "DeleteBackupVaultNotifications",
    "DeleteBackupVaultSharingPolicy", "DeleteFramework", "DeleteRecoveryPoint", "DeleteReportPlan",
    "DeleteRestoreTestingPlan", "DeleteRestoreTestingSelection", "DeleteTieringConfiguration",
    "DescribeBackupAccessPoint", "DescribeBackupJob", "DescribeBackupVault", "DescribeCopyJob",
    "DescribeFramework", "DescribeGlobalSettings", "DescribeProtectedResource", "DescribeRecoveryPoint",
    "DescribeRegionSettings", "DescribeReportJob", "DescribeReportPlan", "DescribeRestoreJob", "DescribeScanJob",
    "DisassociateBackupVaultMpaApprovalTeam", "DisassociateRecoveryPoint", "DisassociateRecoveryPointFromParent",
    "ExportBackupPlanTemplate", "GetBackupPlan", "GetBackupPlanFromJSON", "GetBackupPlanFromTemplate",
    "GetBackupSelection", "GetBackupVaultAccessPolicy", "GetBackupVaultNotifications",
    "GetBackupVaultSharingPolicy", "GetLegalHold", "GetPITRMalwareScanResults", "GetRecoveryPointIndexDetails",
    "GetRecoveryPointRestoreMetadata", "GetRestoreJobMetadata", "GetRestoreTestingInferredMetadata",
    "GetRestoreTestingPlan", "GetRestoreTestingSelection", "GetSupportedResourceTypes", "GetTieringConfiguration",
    "ListBackupAccessPoints", "ListBackupAccessPointsByRecoveryPoint", "ListBackupAccessPointsByResource",
    "ListBackupJobSummaries", "ListBackupJobs", "ListBackupPlanTemplates", "ListBackupPlanVersions",
    "ListBackupPlans", "ListBackupSelections", "ListBackupVaults", "ListCopyJobSummaries", "ListCopyJobs",
    "ListFrameworks", "ListIndexedRecoveryPoints", "ListIndexedRecoveryPointsForSearch", "ListLegalHolds",
    "ListProtectedResources", "ListProtectedResourcesByBackupVault", "ListRecoveryPointsByBackupVault",
    "ListRecoveryPointsByLegalHold", "ListRecoveryPointsByResource", "ListReportJobs", "ListReportPlans",
    "ListRestoreAccessBackupVaults", "ListRestoreJobSummaries", "ListRestoreJobs",
    "ListRestoreJobsByProtectedResource", "ListRestoreTestingPlans", "ListRestoreTestingSelections",
    "ListScanJobSummaries", "ListScanJobs", "ListTags", "ListTieringConfigurations", "PutBackupVaultAccessPolicy",
    "PutBackupVaultLockConfiguration", "PutBackupVaultNotifications", "PutBackupVaultSharingPolicy",
    "PutRestoreValidationResult", "RevokeRestoreAccessBackupVault", "SearchRecoveryPoint", "StartBackupJob",
    "StartCopyJob", "StartReportJob", "StartRestoreJob", "StartScanJob", "StopBackupJob", "TagResource",
    "UntagResource", "UpdateBackupPlan", "UpdateFramework", "UpdateGlobalSettings",
    "UpdateRecoveryPointIndexSettings", "UpdateRecoveryPointLifecycle", "UpdateRegionSettings", "UpdateReportPlan",
    "UpdateRestoreTestingPlan", "UpdateRestoreTestingSelection", "UpdateTieringConfiguration",
])


def _code(text: str) -> str:
    """Terraform with its comments removed (`#`, `//` and `/* */`; none of these stacks has them inside a string
    that matters here): a commented-out block must not count as configured (CodeRabbit, PR 35)."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"(#|//).*", "", text)


def _blocks(kind: str):
    for stack in STACKS:
        for tf in sorted(stack.glob("*.tf")):
            text = _code(tf.read_text(encoding="utf-8"))
            for m in re.finditer(rf'^resource "{kind}" "(\w+)" \{{', text, re.MULTILINE):
                end = re.search(r"^\}", text[m.end():], re.MULTILINE)
                yield f"{tf.relative_to(ROOT)}:{m.group(1)}", text[m.end():m.end() + end.start()]


def test_every_dynamodb_table_can_be_restored_to_a_point_in_time():
    tables = list(_blocks("aws_dynamodb_table"))
    assert tables, "no DynamoDB table found: the pattern no longer matches the stacks"
    bad = [name for name, body in tables
           if not re.search(r"point_in_time_recovery\s*\{\s*enabled\s*=\s*true\s*\}", body)]
    assert not bad, bad


def test_the_audit_database_keeps_backups_and_a_final_snapshot():
    blocks = dict(_blocks("aws_rds_cluster")) | dict(_blocks("aws_db_instance"))
    audit = {n: b for n, b in blocks.items() if "warden-runtime" in n}
    assert audit, "no audit database found in the runtime module"
    for name, body in audit.items():
        assert re.search(r"deletion_protection\s*=\s*true", body), name
        assert re.search(r"skip_final_snapshot\s*=\s*false", body), name
        value = re.search(r"backup_retention_period\s*=\s*(\S+)", body).group(1)
        assert value == "var.audit_db_backup_days", (name, value)
    # The variable can never be 0 (no automated backups): its validation asks for 35 days (Aurora's longest, B19), or 1
    # on the AWS Free plan.
    variables = _code((ROOT / "terraform/modules/warden-runtime/variables.tf").read_text(encoding="utf-8"))
    block = variables.split('variable "audit_db_backup_days" {', 1)[1].split("\n}", 1)[0]
    condition = re.search(r"condition\s*=\s*(.+)", block).group(1).strip()
    assert condition == ("var.audit_db_backup_days == 35 || (var.aws_free_plan && var.audit_db_backup_days >= 1)"), \
        condition


def test_a_commented_out_block_does_not_count():
    body = _code('resource "aws_dynamodb_table" "t" {\n  # point_in_time_recovery {\n  #   enabled = true\n  # }\n}')
    assert not re.search(r"point_in_time_recovery\s*\{\s*enabled\s*=\s*true\s*\}", body)


AUDIT_DAYS = 180  # B19 (owner, 2026-10-17): audit retention at least 180 days - logs, anchors, backups
RUNTIME = ROOT / "terraform" / "modules" / "warden-runtime"


def test_every_runtime_log_group_keeps_its_logs_at_least_180_days():
    groups = [(name, body) for name, body in _blocks("aws_cloudwatch_log_group") if "warden-runtime" in name]
    assert len(groups) >= 4, "the pattern no longer finds the runtime's log groups"
    short = [name for name, body in groups
             if int(re.search(r"retention_in_days\s*=\s*(\d+)", body).group(1)) < AUDIT_DAYS]
    assert not short, short
    # A Lambda without its own log group gets one from AWS that terraform does not hold to this; only the ack
    # function has none, and its role has no permission at all - it writes no log.
    code = {tf.name: _code(tf.read_text(encoding="utf-8")) for tf in RUNTIME.glob("*.tf")}
    functions = {m for text in code.values() for m in re.findall(r'^resource "aws_lambda_function" "(\w+)"', text, re.MULTILINE)}
    groups_by_name = {name.rsplit(":", 1)[1] for name, _ in groups}
    # Each function's log group is the resource of the same name (main added webhook_auth and pager).
    assert {f for f in functions if f not in groups_by_name} == {"ack"}
    found = re.search(r'resource "aws_iam_role" "ack" \{.*?^\}', code["frontdoor.tf"], re.DOTALL | re.MULTILINE)
    assert found, "the ack role is no longer in frontdoor.tf: check this test"
    ack_role = found.group(0)
    # Outside its own block the role is named only as the function's execution role (.arn): nothing attaches, binds
    # or loops a policy onto it (by id, name, a local or for_each).
    rest = "".join(code.values()).replace(ack_role, "")
    assert set(re.findall(r"\baws_iam_role\.ack\b(\.\w+)?", rest)) == {".arn"}
    assert "inline_policy" not in ack_role
    assert "managed_policy_arns" not in ack_role


def test_anchors_and_the_witness_stay_locked_at_least_180_days():
    for tf, resource in (("anchors.tf", "anchors"), ("witness.tf", "witness")):
        text = _code((RUNTIME / tf).read_text(encoding="utf-8"))
        lock = re.search(rf'resource "aws_s3_bucket_object_lock_configuration" "{resource}" \{{.*?^\}}', text,
                         re.DOTALL | re.MULTILINE).group(0)
        assert re.search(r'mode\s*=\s*"COMPLIANCE"', lock), tf
        assert re.search(r"days\s*=\s*var\.anchor_retention_days", lock), tf
    runtime = _code((ROOT / "terraform" / "runtime" / "main.tf").read_text(encoding="utf-8"))
    found = re.search(r'^module "runtime" \{.*?^\}', runtime, re.DOTALL | re.MULTILINE)
    assert found, 'terraform/runtime/main.tf has no module "runtime" block'
    days = re.search(r"^\s*anchor_retention_days\s*=\s*(\d+)\s*$", found.group(0), re.MULTILINE)
    assert days, "terraform/runtime/main.tf sets no anchor_retention_days: the module's 1-day default applies"
    assert int(days.group(1)) >= AUDIT_DAYS


def _resource(text: str, kind: str, name: str) -> str:
    found = re.search(rf'^resource "{kind}" "{name}" \{{.*?^\}}', text, re.DOTALL | re.MULTILINE)
    assert found, f"{kind}.{name} is not in the runtime module"
    return found.group(0)


def test_one_monthly_audit_copy_in_this_regions_vault_kept_past_aurora_s_35_days():
    """B19 (owner decision 2026-10-20): 35 days of automated backups, plus one AWS Backup copy a month - same region, the
    vault's AWS-managed key, no cross-region copy, no continuous backup - switchable, on by default."""
    tf = _code((RUNTIME / "backup.tf").read_text(encoding="utf-8"))
    plan = _resource(tf, "aws_backup_plan", "audit")
    assert re.search(r'schedule\s*=\s*"cron\(0 21 1 \* \? \*\)"', plan)  # the 1st of each month
    for absent in ("copy_action", "enable_continuous_backup", "cold_storage_after", "lifecycle"):
        assert absent not in plan, absent
    assert "kms_key_arn" not in _resource(tf, "aws_backup_vault", "audit")  # AWS-managed key
    selection = _resource(tf, "aws_backup_selection", "audit")
    assert re.search(r"resources\s*=\s*\[local\.audit_db\.arn\]", selection)
    assert "selection_tag" not in selection  # this database only
    assert "condition" not in selection
    assert re.search(r"audit_backup\s*=\s*var\.audit_monthly_backup && !var\.aws_free_plan \? 1 : 0", tf)
    # The vault outlives the switch; the plan, the selection and the role go with it.
    assert re.search(r"count\s*=\s*local\.audit_vault\b", _resource(tf, "aws_backup_vault", "audit"))
    assert re.search(r"audit_vault\s*=\s*var\.aws_free_plan \? 0 : 1", tf)
    variables = _code((RUNTIME / "variables.tf").read_text(encoding="utf-8"))
    block = variables.split('variable "audit_monthly_backup" {', 1)[1].split("\n}", 1)[0]
    assert re.search(r"default\s*=\s*true", block)
    root = _code((ROOT / "terraform" / "runtime" / "main.tf").read_text(encoding="utf-8"))
    # Fail closed: only "false" turns it off ("True", "yes", a trailing space all keep it on).
    assert ('audit_monthly_backup = lower(trimspace(lookup(local.tf, "audit_monthly_backup", "true"))) != "false"'
            in " ".join(root.split()))


def test_the_backup_role_snapshots_this_cluster_into_this_vault_and_deletes_nothing():
    tf = _code((RUNTIME / "backup.tf").read_text(encoding="utf-8"))
    role = _resource(tf, "aws_iam_role", "audit_backup")
    assert "permissions_boundary = var.permissions_boundary_arn" in " ".join(role.split())
    policy = _resource(tf, "aws_iam_role_policy", "audit_backup")
    assert "NotAction" not in policy
    action_lines = re.findall(r"Action\s*=\s*(\[[^\]]*\]|\"[^\"]*\")", policy)
    actions = {a for line in action_lines for a in re.findall(r'"([^"]*)"', line)}  # every string, wildcards too
    assert actions == {"rds:CreateDBClusterSnapshot", "rds:AddTagsToResource", "rds:DescribeDBClusters",
                       "rds:DescribeDBClusterSnapshots", "rds:ListTagsForResource",
                       "backup:DescribeBackupVault", "backup:CopyIntoBackupVault", "backup:TagResource",
                       "kms:DescribeKey", "kms:CreateGrant"}
    # Nothing account-wide, as a string or in a list.
    assert not re.search(r'Resource\s*=\s*(?:"\*"|\[[^\]]*"\*"[^\]]*\])', policy)
    assert "local.audit_db.arn" in policy
    assert "cluster-snapshot:awsbackup:*" in policy
    assert '"kms:GrantIsForAWSResource" = "true"' in policy
    assert "aws_backup_vault.audit[0].arn" in policy
    # Nothing deletes a copy: the boundary denies it to every role it bounds, this one included.
    boundary = json.loads((ROOT / "iam" / "ops" / "boundary.json").read_text(encoding="utf-8"))
    always = next(st for st in boundary["Statement"] if st.get("Sid") == "DenyAlways")
    assert any(fnmatch.fnmatchcase("rds:DeleteDBClusterSnapshot", a) for a in always["Action"])


def test_the_deploy_role_manages_only_the_audit_vault_and_plan_from_its_own_policy():
    """The deploy role's grant is a managed policy of its own (deploy-backup): its main one is near IAM's 6,144
    characters. The boundary lets backup in only within the region."""
    doc = json.loads((ROOT / "iam" / "ops" / "deploy-backup.json").read_text(encoding="utf-8"))
    by_sid = {st["Sid"]: st for st in doc["Statement"]}
    assert all(st["Effect"] == "Allow" for st in doc["Statement"])
    region = r_region()
    assert by_sid["TheAuditVaultPlanAndSelection"]["Resource"] == [
        f"arn:aws:backup:{region}:*:backup-vault:warden-ops-*", f"arn:aws:backup:{region}:*:backup-plan:*"]
    assert not [a for a in by_sid["TheAuditVaultPlanAndSelection"]["Action"]
                if "RecoveryPoint" in a or a.startswith("backup:Start") or "*" in a]
    assert by_sid["TheVaultsAwsManagedKeyThroughBackupOnly"]["Condition"] == {
        "StringEquals": {"kms:ViaService": f"backup.{region}.amazonaws.com"}}
    passing = by_sid["PassTheBackupRoleToBackupOnly"]
    assert passing["Resource"] == "arn:aws:iam::*:role/warden-ops-audit-backup"
    assert passing["Condition"] == {"StringEquals": {"iam:PassedToService": "backup.amazonaws.com"}}
    boundary = json.loads((ROOT / "iam" / "ops" / "boundary.json").read_text(encoding="utf-8"))
    ceiling = next(st for st in boundary["Statement"] if st.get("Sid") == "CeilingRegional")
    assert sorted(a for a in ceiling["Action"] if a.startswith("backup-storage:")) == ["backup-storage:MountCapsule"]
    assert ceiling["Condition"] == {"StringEquals": {"aws:RequestedRegion": region}}
    # The ceiling lets in exactly what the deploy role and the backup role use. So no role the boundary bounds can
    # delete a copy, take one out (CopyFromBackupVault), restore (a person restores), change a copy's lifecycle, set a
    # vault policy or lock, or make another kind of vault. IAM matches action names case-insensitively.
    patterns = [a.split(":", 1)[1].lower() for a in ceiling["Action"] if a.startswith("backup:")]
    allowed = {a for a in BACKUP_ACTIONS if any(fnmatch.fnmatchcase(a.lower(), p) for p in patterns)}
    used = {a.split(":", 1)[1] for a in by_sid["TheAuditVaultPlanAndSelection"]["Action"]}
    used |= {"DescribeBackupVault", "CopyIntoBackupVault", "TagResource"}  # the backup role's (backup.tf)
    assert used <= BACKUP_ACTIONS
    assert allowed == used


def r_region() -> str:
    import sys

    sys.path.insert(0, str(ROOT / "src"))
    from warden.environments import EnvironmentPolicies, names

    return names(EnvironmentPolicies.load().runtime_environment).region


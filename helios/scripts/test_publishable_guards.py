"""Tests for the two publish guards: scrub_tfjson.py and check_publishable.py.

Stdlib unittest, because the scripts are stdlib-only repo tools, not part of the helios-ai package:
    python -m unittest discover -s scripts

The fixture below is deliberately secret-shaped (see ALLOWED_PATHS in check_publishable.py): a
scrubber tested against text that does not look like a secret proves nothing.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_publishable  # noqa: E402
import scrub_tfjson  # noqa: E402

ACCOUNT = "987654321098"
PUBLIC_IP = "54.23.10.7"
SUBNET = "subnet-0123456789abcdef0"
VPC = "vpc-0fedcba9876543210"
ALB_ID = "abeeb3492689b54c"
UUID = "6ed06e77-c363-4349-1584-ca21c7f7f5b6"
SECRETS = ["hunter2-db-master", "Rand0m-Result-Value", "env-api-key-value", "s3cr3t-constant"]

PLAN = {
    "format_version": "1.2",
    "terraform_version": "1.9.0",
    "variables": {"db_password": {"value": "hunter2-db-master"}},
    "planned_values": {"root_module": {"resources": [
        {"address": "aws_vpc.main", "mode": "managed", "type": "aws_vpc", "name": "main",
         "values": {"id": VPC, "cidr_block": "10.0.0.0/16",
                    "arn": f"arn:aws:ec2:eu-west-2:{ACCOUNT}:vpc/{VPC}",
                    "tags": {"Name": "main", "Owner": "someone@corp.test"}}},
        {"address": "aws_subnet.a", "mode": "managed", "type": "aws_subnet", "name": "a",
         "values": {"id": SUBNET, "vpc_id": VPC, "availability_zone": "eu-west-2a",
                    "arn": f"arn:aws:ec2:eu-west-2:{ACCOUNT}:subnet/{SUBNET}"}},
        {"address": "aws_db_instance.db", "mode": "managed", "type": "aws_db_instance",
         "name": "db", "values": {"identifier": "db", "multi_az": True,
                                  "password": "hunter2-db-master", "username": "admin"},
         "sensitive_values": {"password": True}},
        {"address": "aws_lambda_function.fn", "mode": "managed", "type": "aws_lambda_function",
         "name": "fn", "values": {
             "function_name": "fn", "role": f"arn:aws:iam::{ACCOUNT}:role/fn",
             "vpc_config": [{"subnet_ids": [SUBNET],
                             "security_group_ids": ["sg-0aaaabbbbccccdddd"]}],
             "environment": [{"variables": {"API_KEY": "env-api-key-value",
                                            "UPSTREAM": PUBLIC_IP}}]}},
        {"address": "aws_lb.web", "mode": "managed", "type": "aws_lb", "name": "web", "values": {
            "arn": f"arn:aws:elasticloadbalancing:eu-west-2:{ACCOUNT}:loadbalancer/app/web/{ALB_ID}",
            "subnets": [SUBNET]}},
        {"address": "aws_eks_node_group.ng", "mode": "managed", "type": "aws_eks_node_group",
         "name": "ng", "values": {"arn": f"arn:aws:eks:eu-west-2:{ACCOUNT}:nodegroup/c/ng/{UUID}",
                                  "subnet_ids": [SUBNET]}},
        {"address": "aws_nat_gateway.nat", "mode": "managed", "type": "aws_nat_gateway",
         "name": "nat", "values": {"subnet_id": SUBNET, "public_ip": PUBLIC_IP}},
        {"address": "random_password.db", "mode": "managed", "type": "random_password",
         "name": "db", "values": {"result": "Rand0m-Result-Value", "length": 24}},
    ]}},
    "resource_changes": [{"address": "aws_db_instance.db",
                          "change": {"after": {"password": "hunter2-db-master"}}}],
    "configuration": {"root_module": {"resources": [
        {"address": "aws_subnet.a", "mode": "managed", "type": "aws_subnet", "name": "a",
         "expressions": {"vpc_id": {"references": ["aws_vpc.main.id", "aws_vpc.main"]},
                         "cidr_block": {"constant_value": "s3cr3t-constant"}},
         "count_expression": {"constant_value": 2}},
        {"address": "aws_db_instance.db", "mode": "managed", "type": "aws_db_instance",
         "name": "db", "expressions": {
             "password": {"references": ["random_password.db.result", "random_password.db"]},
             "db_subnet_group_name": {"references": ["aws_db_subnet_group.db.name"]}}},
        {"address": "random_password.db", "mode": "managed", "type": "random_password",
         "name": "db", "expressions": {"length": {"constant_value": 24}}},
    ]}},
}


class ScrubTfjson(unittest.TestCase):
    def setUp(self) -> None:
        self.out = scrub_tfjson.scrub(json.loads(json.dumps(PLAN)))
        self.text = json.dumps(self.out)

    def test_no_secret_survives(self) -> None:
        for s in [*SECRETS, ACCOUNT, PUBLIC_IP, "someone@corp.test", "API_KEY", "admin"]:
            self.assertNotIn(s, self.text)
        for key in ("variables", "resource_changes"):
            self.assertNotIn(key, self.out)

    def test_output_passes_check_publishable(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d, "plan.json")
            p.write_text(json.dumps(self.out, indent=2), encoding="utf-8")
            self.assertEqual(check_publishable.scan([p], root=pathlib.Path(d)), [])

    def test_shape_and_kept_types(self) -> None:
        self.assertEqual(self.out["format_version"], "1.2")
        types = [r["type"] for r in self.out["planned_values"]["root_module"]["resources"]]
        self.assertEqual(types, ["aws_vpc", "aws_subnet", "aws_db_instance",
                                 "aws_lambda_function", "aws_lb", "aws_eks_node_group",
                                 "aws_nat_gateway"])
        vpc = self.out["planned_values"]["root_module"]["resources"][0]["values"]
        self.assertEqual(vpc["tags"], {"Name": "main"})
        self.assertIn(":123456789012:", vpc["arn"])

    def test_ids_replaced_consistently(self) -> None:
        self.assertNotIn(SUBNET, self.text)
        self.assertNotIn(VPC, self.text)
        resources = self.out["planned_values"]["root_module"]["resources"]
        res = {r["address"]: r["values"] for r in resources}
        subnet_id = res["aws_subnet.a"]["id"]
        self.assertRegex(subnet_id, r"^subnet-[0-9a-f]{17}$")
        self.assertEqual(res["aws_lambda_function.fn"]["vpc_config"][0]["subnet_ids"], [subnet_id])
        self.assertEqual(res["aws_nat_gateway.nat"]["subnet_id"], subnet_id)
        self.assertTrue(res["aws_subnet.a"]["arn"].endswith("/" + subnet_id))
        self.assertEqual(res["aws_subnet.a"]["vpc_id"], res["aws_vpc.main"]["id"])
        self.assertNotEqual(subnet_id, res["aws_vpc.main"]["id"])

    def test_load_balancer_ids_and_uuids_replaced(self) -> None:
        self.assertNotIn(ALB_ID, self.text)
        self.assertNotIn(UUID, self.text)
        resources = self.out["planned_values"]["root_module"]["resources"]
        res = {r["address"]: r["values"] for r in resources}
        self.assertTrue(res["aws_lb.web"]["arn"].endswith("/app/web/0000000000000001"))
        self.assertTrue(res["aws_eks_node_group.ng"]["arn"].endswith(
            "/ng/00000000-0000-0000-0000-a00000000001"))

    def test_references_kept_constants_dropped(self) -> None:
        cfg = {r["address"]: r for r in self.out["configuration"]["root_module"]["resources"]}
        self.assertEqual(cfg["aws_subnet.a"]["expressions"],
                         {"vpc_id": {"references": ["aws_vpc.main.id", "aws_vpc.main"]}})
        self.assertEqual(cfg["aws_db_instance.db"]["expressions"],
                         {"db_subnet_group_name": {"references": ["aws_db_subnet_group.db.name"]}})
        self.assertNotIn("random_password.db", cfg)


class ScrubReadsOnlyInsideCwd(unittest.TestCase):
    """The input path can come from an agent: a path out of the working directory is refused."""

    def _main(self, cwd: pathlib.Path, arg: str) -> tuple[int, str]:
        # A real text stream: main() reconfigures stdout to UTF-8, which a StringIO cannot do.
        old_cwd, old_argv, out = os.getcwd(), sys.argv, io.TextIOWrapper(io.BytesIO())
        try:
            os.chdir(cwd)
            sys.argv = ["scrub_tfjson.py", arg]
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                code = scrub_tfjson.main()
            out.flush()
            return code, out.buffer.getvalue().decode("utf-8")
        finally:
            os.chdir(old_cwd)
            sys.argv = old_argv

    def test_inside_is_read_outside_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            work, outside = pathlib.Path(d, "work"), pathlib.Path(d, "secret.json")
            sibling = pathlib.Path(d, "work-other", "secret.json")  # shares work's prefix
            sibling.parent.mkdir(parents=True)
            work.mkdir()
            (work / "plan.json").write_text(json.dumps(PLAN), encoding="utf-8")
            for p in (outside, sibling):
                p.write_text(json.dumps(PLAN), encoding="utf-8")
            code, out = self._main(work, "plan.json")
            self.assertEqual(code, 0)
            self.assertIn("aws_vpc.main", out)
            refused = ["../secret.json", str(outside), "sub/../../secret.json",
                       "../work-other/secret.json"]
            try:  # a link inside the folder to a file outside it (needs privilege on Windows)
                (work / "link.json").symlink_to(outside)
                refused.append("link.json")
            except OSError:
                pass
            for arg in refused:
                self.assertEqual(self._main(work, arg), (2, ""), arg)


class ScrubKeepsWhatHeliosReads(unittest.TestCase):
    """A type the scrubber drops is a fixture that disagrees with the real input: the Wave 4 plan's
    IAM scenarios went from a verdict to INCONCLUSIVE because `aws_iam_role` was dropped."""

    def test_every_type_the_graph_reads_is_kept(self) -> None:
        src = (ROOT / "crates/helios-graph/src/resource.rs").read_text(encoding="utf-8")
        tables = [src.split(f"const {name}")[1].split("];")[0] for name in ("KINDS", "LINK_ONLY")]
        read = {t for table in tables for t in re.findall(r'"(aws_[a-z0-9_]+)"', table)}
        self.assertGreaterEqual(len(read), 27)  # 18 kinds + 9 link-only
        self.assertEqual(sorted(read - scrub_tfjson.KEEP_TYPES), [])


class CheckPublishable(unittest.TestCase):
    def _scan(self, name: str, content: str) -> list[str]:
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d, name)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
            return check_publishable.scan([p], root=pathlib.Path(d))

    def test_forbidden_names(self) -> None:
        for name in ("tfplan", "tfplan.fs", "x.tfplan", "plan.out", "terraform.tfstate",
                     "prod.tfvars"):
            self.assertTrue(self._scan(name, "{}"), name)
        self.assertEqual(self._scan("terraform.tfvars.example", "{}"), [])

    def test_public_ip_and_account(self) -> None:
        self.assertTrue(self._scan("a.json", f'"ip": "{PUBLIC_IP}"'))
        self.assertTrue(self._scan("a.json", f'"arn:aws:iam::{ACCOUNT}:role/x"'))
        for fine in ("10.1.2.3", "172.16.0.1", "192.168.1.1", "127.0.0.1", "0.0.0.0/0",
                     "169.254.169.254", "192.0.2.10", "198.51.100.1", "203.0.113.9",
                     "1.2.3.400", "arn:aws:iam::123456789012:role/x"):
            self.assertEqual(self._scan("a.json", fine), [], fine)


if __name__ == "__main__":
    unittest.main()

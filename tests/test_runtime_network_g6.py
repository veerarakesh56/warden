"""G6: the runtime's own network and model. terraform/runtime makes a VPC across two availability zones - private
subnets for the workers, Lambdas and audit database, public ones for the way out through a NAT gateway (one for a lab
window, one per zone for production), a free S3 gateway endpoint - and the module runs on its private subnets. The
model is set for the llm zone alone, by the deploy, never by a setting anyone can change in SSM."""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
NET = (ROOT / "terraform" / "runtime" / "network.tf").read_text(encoding="utf-8")
MAIN = (ROOT / "terraform" / "runtime" / "main.tf").read_text(encoding="utf-8")
COMPUTE = (ROOT / "terraform" / "modules" / "warden-runtime" / "compute.tf").read_text(encoding="utf-8")


def test_the_runtime_runs_in_its_own_private_subnets_across_two_zones():
    assert re.search(r"vpc_id\s+= aws_vpc\.runtime\.id", MAIN) and re.search(r"private_subnet_ids\s+= aws_subnet\.private\[\*\]\.id", MAIN)
    assert "slice(data.aws_availability_zones.here.names, 0, 2)" in NET
    private = NET[NET.index('resource "aws_subnet" "private"'):NET.index('resource "aws_internet_gateway"')]
    assert "map_public_ip_on_launch" not in private  # private: no public address
    assert "nat_gateway_id         = aws_nat_gateway.runtime[min(count.index, var.nat_gateways - 1)].id" in NET
    assert "contains([1, 2], var.nat_gateways)" in NET
    assert 'vpc_endpoint_type = "Gateway"' in NET and '"com.amazonaws.${local.config.aws_region}.s3"' in NET
    assert not re.search(r"\b(?:ap|us|eu|ca|sa|me|af|il)-[a-z]+-\d\b", NET)  # no region


def test_only_the_llm_zone_is_told_the_model_and_only_by_the_deploy():
    from warden import settings

    assert 'each.key == "llm" && var.model_provider != "" ? { WARDEN_PROVIDER = var.model_provider, WARDEN_MODEL = var.model }' in COMPUTE
    assert re.search(r'model_provider\s+= lookup\(local\.tf, "model_provider", ""\)', MAIN)
    assert "WARDEN_PROVIDER" not in settings.LOADABLE  # SSM's env/ path can never re-point the model traffic


def test_the_workers_way_out_outlives_them_when_the_runtime_is_paused():
    """2026-10-11 (run 38121022138): pausing removed the services and the NAT route in one apply; the tasks, told to
    stop on instances that had lost their route, never heard it, the services stayed DRAINING until Terraform gave up
    after twenty minutes, and the instances kept running. The module now depends on the route, so on a pause its
    services and instances are removed before the route and the NAT."""
    module = MAIN[MAIN.index('module "runtime" {'):MAIN.index("# A slot the owner made by hand")]
    assert re.search(r"depends_on\s+= \[terraform_data\.environment_is_known, aws_route\.private_out\]", module)
    route = NET[NET.index('resource "aws_route" "private_out"'):NET.index('resource "aws_route_table_association" "private"')]
    assert "count                  = local.paused ? 0 : 2" in route and "nat_gateway_id" in route
    assert 'for_each        = var.paused ? {} : local.zones' in COMPUTE  # the services the pause removes

"""Wave 4 injectors, guards and the fix allow-list - against a stateful fake stack, no AWS.

⚠ What this proves: every inject changes the state it claims to, every revert puts back EXACTLY
what was captured, the guard refuses what is not ours, and the allow-list refuses every command
shape it should. It proves nothing about the real APIs - scripts/preflight_fullstack_ops.py asks
those.
"""

from __future__ import annotations

import copy
import io
import json

import pytest
from scenarios import ops_fullstack as fs
from scenarios.ops import OpError

ROOT_ARN = "arn:aws:iam::111122223333:root"
TAGGED = {"Project": "warden-fullstack"}


# =========================================================================== the fake stack


class World:
    """One mutable state for every fake client, so a snapshot sees the whole stack."""

    def __init__(self):
        self.lambdas = {
            fn: {"Timeout": 10, "Environment": {"Variables": dict(env)}, "LastUpdateStatus": "Successful",
                 "FunctionArn": f"arn:aws:lambda:ap-south-2:111122223333:function:{fn}"}
            for fn, env in {
                "warden-pg-fs-checkout": {"TABLE_NAME": "warden-pg-fs-carts", "CHECKOUT_PAYLOAD_SCHEMA": "v1",
                                          "DDB_EXTRA_LATENCY_MS": "0"},
                "warden-pg-fs-order-processor": {"DB_HOST": "warden-pg-fs-aurora.cluster-x.rds.amazonaws.com"},
                "warden-pg-fs-reconciler": {"RECONCILE_LOOKUP": "by_id"},
                "warden-pg-fs-notifier": {}, "warden-pg-fs-ops": {},
            }.items()}
        self.tags = {fn: dict(TAGGED) for fn in self.lambdas}
        self.alias = {"warden-pg-fs-checkout": "7"}
        self.versions: dict[str, dict] = {"7": copy.deepcopy(self.lambdas["warden-pg-fs-checkout"])}
        self.concurrency: dict[str, int] = {}
        self.esm = {"uuid-orders": {"State": "Enabled",
                                    "EventSourceArn": "arn:aws:sqs:ap-south-2:111122223333:warden-pg-fs-orders"}}
        self.iam = {
            "warden-pg-fs-checkout": {"inline": {"Version": "2012-10-17", "Statement": [
                {"Sid": "WriteCarts", "Effect": "Allow", "Action": ["dynamodb:PutItem"],
                 "Resource": "arn:aws:dynamodb:ap-south-2:111122223333:table/warden-pg-fs-carts"},
                {"Sid": "Publish", "Effect": "Allow", "Action": ["sns:Publish"],
                 "Resource": "arn:aws:sns:ap-south-2:111122223333:warden-pg-fs-order-events"}]}},
            "warden-pg-fs-ecs-exec": {"secrets": {"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue",
                 "Resource": "arn:aws:secretsmanager:ap-south-2:111122223333:secret:warden-pg-fs-db-app"}]}},
            "warden-pg-fs-orders-api-task": {"warden-pg-fs-db-connect": {"Version": "2012-10-17", "Statement": [
                {"Sid": "ConnectAsApp", "Effect": "Allow", "Action": ["rds-db:connect"],
                 "Resource": ["arn:aws:rds-db:ap-south-2:111122223333:dbuser:*/app"]}]}},
        }
        self.queues = {
            "warden-pg-fs-orders": {"visible": 0, "Policy": None},
            "warden-pg-fs-orders-dlq": {"visible": 0, "Policy": None},
            "warden-pg-fs-notifications": {"visible": 0, "Policy": json.dumps({"Statement": [{
                "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"}, "Action": "sqs:SendMessage",
                "Condition": {"ArnEquals": {"aws:SourceArn": "arn:aws:sns:ap-south-2:111122223333:warden-pg-fs-order-events"}}}]})},
        }
        self.table = {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}
        self.sg_rules = [{"IpProtocol": "tcp", "FromPort": 6379, "ToPort": 6379,
                          "UserIdGroupPairs": [{"GroupId": "sg-app1"}]}]
        self.sg_name = "warden-pg-fs-redis"
        self.redis_node_type = "cache.t4g.micro"
        self.redis_status = "available"
        self.redis_used = 10
        self.writer = "warden-pg-fs-aurora-1"
        self.ecs_td = "arn:aws:ecs:ap-south-2:111122223333:task-definition/warden-pg-fs-orders-api:3"
        self.tds = {self.ecs_td: {"family": "warden-pg-fs-orders-api", "cpu": "512", "memory": "1024",
                                  "containerDefinitions": [{"name": "orders-api", "image": "ecr/app:v1",
                                                            "environment": [{"name": "ALLOC_MB", "value": "0"}]}]}}
        self.forced = 0
        self.tg_path = "/health"
        self.secret = json.dumps({"username": "app", "dbname": "shop", "port": 5432, "host": "h", "reader": "r"})
        self.indexes = {"orders_customer_id_idx": "CREATE INDEX orders_customer_id_idx ON public.orders USING btree (customer_id)"}
        self.held_apps: list[str] = []
        self.rule = "ENABLED"
        self.ns_labels = {"project": "warden-fullstack"}
        self.configmap = {"CATALOG_PAGE_SIZE": "20", "OTHER": "x"}
        self.k8s_secret = {"API_TOKEN": "dG9r", "UNUSED": "eA=="}
        self.deployments = {
            "catalog-api": {"spec": {"replicas": 2, "template": {"metadata": {}, "spec": {"containers": [{
                "name": "catalog-api", "image": "ecr/app:v1",
                "env": [{"name": "API_TOKEN", "valueFrom": {"secretKeyRef": {"name": "catalog-secret", "key": "API_TOKEN"}}}],
                "readinessProbe": {"httpGet": {"path": "/health", "port": 8080}}}]}}},
                "status": {"readyReplicas": 2, "updatedReplicas": 2}},
            "cart-worker": {"spec": {"replicas": 1, "template": {"metadata": {}, "spec": {"containers": [{
                "name": "cart-worker", "image": "ecr/app:v1"}]}}},
                "status": {"readyReplicas": 1, "updatedReplicas": 1}},
        }

    def snapshot(self) -> dict:
        """Everything a fault may change - minus bookkeeping that is not state (published
        versions, registered revisions, restart annotations, purge calls)."""
        deps = {n: [{k: v for k, v in c.items()} for c in d["spec"]["template"]["spec"]["containers"]]
                for n, d in self.deployments.items()}
        return copy.deepcopy({
            "lambdas": {fn: (c["Timeout"], c["Environment"]) for fn, c in self.lambdas.items()},
            "alias": self.alias, "concurrency": self.concurrency,
            "esm": {k: v["State"] for k, v in self.esm.items()}, "iam": self.iam,
            "queues": self.queues, "table": self.table, "sg": self.sg_rules, "redis": self.redis_used,
            "writer": self.writer, "ecs_td": self.ecs_td, "tg": self.tg_path, "secret": self.secret,
            "indexes": self.indexes, "held": self.held_apps,
            "rule": self.rule, "configmap": self.configmap, "k8s_secret": self.k8s_secret, "deps": deps,
        })


class Err(Exception):
    pass


class Lam:
    def __init__(self, w: World):
        self.w = w

    def get_function_configuration(self, FunctionName, Qualifier=None):
        if Qualifier:
            return copy.deepcopy(self.w.versions[self.w.alias[FunctionName]])
        return copy.deepcopy(self.w.lambdas[FunctionName])

    def list_tags(self, Resource):
        return {"Tags": self.w.tags[Resource.rsplit(":", 1)[-1]]}

    def get_alias(self, FunctionName, Name):
        return {"FunctionVersion": self.w.alias[FunctionName]}

    def update_function_configuration(self, FunctionName, **kw):
        self.w.lambdas[FunctionName].update(copy.deepcopy(kw))

    def publish_version(self, FunctionName, Description=""):
        v = str(max(int(k) for k in self.w.versions) + 1)
        self.w.versions[v] = copy.deepcopy(self.w.lambdas[FunctionName])
        return {"Version": v}

    def update_alias(self, FunctionName, Name, FunctionVersion):
        self.w.alias[FunctionName] = FunctionVersion

    def get_function_concurrency(self, FunctionName):
        n = self.w.concurrency.get(FunctionName)
        return {} if n is None else {"ReservedConcurrentExecutions": n}

    def put_function_concurrency(self, FunctionName, ReservedConcurrentExecutions):
        self.w.concurrency[FunctionName] = ReservedConcurrentExecutions

    def delete_function_concurrency(self, FunctionName):
        self.w.concurrency.pop(FunctionName, None)

    def list_event_source_mappings(self, FunctionName):
        if FunctionName != "warden-pg-fs-order-processor":
            return {"EventSourceMappings": []}
        return {"EventSourceMappings": [{"UUID": k, **v} for k, v in self.w.esm.items()]}

    def update_event_source_mapping(self, UUID, Enabled):
        self.w.esm[UUID]["State"] = "Enabled" if Enabled else "Disabled"

    def invoke(self, FunctionName, InvocationType, Payload):
        op = json.loads(Payload)
        if op["op"] == "fill":
            self.w.redis_used += op["mb"]
        elif op["op"] == "flush_prefix":
            self.w.redis_used = 10
        body = {"used_memory": self.w.redis_used, "maxmemory": 500}
        return {"Payload": io.BytesIO(json.dumps(body).encode())}


class Iam:
    def __init__(self, w):
        self.w = w

    def list_role_tags(self, RoleName):
        return {"Tags": [{"Key": "Project", "Value": "warden-fullstack"}]}

    def list_role_policies(self, RoleName):
        return {"PolicyNames": list(self.w.iam[RoleName])}

    def get_role_policy(self, RoleName, PolicyName):
        return {"PolicyDocument": copy.deepcopy(self.w.iam[RoleName][PolicyName])}

    def put_role_policy(self, RoleName, PolicyName, PolicyDocument):
        doc = json.loads(PolicyDocument)
        if not doc.get("Statement"):  # as IAM: MalformedPolicyDocument
            raise RuntimeError("MalformedPolicyDocument: Policy statement must contain resources/actions")
        self.w.iam[RoleName][PolicyName] = doc

    def delete_role_policy(self, RoleName, PolicyName):
        del self.w.iam[RoleName][PolicyName]


class Sqs:
    def __init__(self, w):
        self.w = w

    def get_queue_url(self, QueueName):
        return {"QueueUrl": f"https://sqs.ap-south-2.amazonaws.com/111122223333/{QueueName}"}

    def _q(self, url):
        return self.w.queues[url.rsplit("/", 1)[-1]]

    def list_queue_tags(self, QueueUrl):
        return {"Tags": dict(TAGGED)}

    def get_queue_attributes(self, QueueUrl, AttributeNames):
        q, name = self._q(QueueUrl), QueueUrl.rsplit("/", 1)[-1]
        attrs = {"ApproximateNumberOfMessages": str(q["visible"]),
                 "QueueArn": f"arn:aws:sqs:ap-south-2:111122223333:{name}"}
        if q["Policy"] is not None:
            attrs["Policy"] = q["Policy"]
        return {"Attributes": attrs}

    def set_queue_attributes(self, QueueUrl, Attributes):
        self._q(QueueUrl)["Policy"] = Attributes["Policy"] or None

    def send_message(self, QueueUrl, MessageBody):
        self._q(QueueUrl)["visible"] += 1
        self.w.queues["warden-pg-fs-orders-dlq"]["visible"] += 1  # dead-lettered at once, for the fake

    def purge_queue(self, QueueUrl):
        self._q(QueueUrl)["visible"] = 0


class Ddb:
    def __init__(self, w):
        self.w = w

    def describe_table(self, TableName):
        return {"Table": {"TableArn": "arn:aws:dynamodb:ap-south-2:111122223333:table/" + TableName,
                          "TableStatus": "ACTIVE", "ProvisionedThroughput": dict(self.w.table)}}

    def list_tags_of_resource(self, ResourceArn):
        return {"Tags": [{"Key": "Project", "Value": "warden-fullstack"}]}

    def update_table(self, TableName, ProvisionedThroughput):
        self.w.table = dict(ProvisionedThroughput)


class Ec2:
    def __init__(self, w):
        self.w = w

    def describe_security_groups(self, GroupIds):
        return {"SecurityGroups": [{"GroupName": self.w.sg_name, "IpPermissions": copy.deepcopy(self.w.sg_rules),
                                    "Tags": [{"Key": "Project", "Value": "warden-fullstack"}]}]}

    def revoke_security_group_ingress(self, GroupId, IpPermissions):
        gone = {(p.get("IpProtocol"), p.get("FromPort"), p.get("ToPort"), g["GroupId"])
                for p in IpPermissions for g in p.get("UserIdGroupPairs") or []}
        kept = []
        for r in self.w.sg_rules:
            pairs = [g for g in r.get("UserIdGroupPairs") or []
                     if (r.get("IpProtocol"), r.get("FromPort"), r.get("ToPort"), g["GroupId"]) not in gone]
            if pairs:
                kept.append({**r, "UserIdGroupPairs": pairs})
        self.w.sg_rules = kept

    def authorize_security_group_ingress(self, GroupId, IpPermissions):
        for r in IpPermissions:
            if r in self.w.sg_rules:
                raise Err("InvalidPermission.Duplicate")
            self.w.sg_rules.append(copy.deepcopy(r))


class ElastiCache:
    def __init__(self, w):
        self.w = w

    def describe_replication_groups(self, ReplicationGroupId):
        return {"ReplicationGroups": [{
            "ARN": f"arn:aws:elasticache:ap-south-2:111122223333:replicationgroup:{ReplicationGroupId}",
            "MemberClusters": [f"{ReplicationGroupId}-001"], "Status": self.w.redis_status}]}

    def describe_cache_clusters(self, CacheClusterId):
        return {"CacheClusters": [{"CacheNodeType": self.w.redis_node_type}]}

    def list_tags_for_resource(self, ResourceName):
        return {"TagList": [{"Key": "Project", "Value": "warden-fullstack"}]}

    def modify_replication_group(self, ReplicationGroupId, CacheNodeType, ApplyImmediately):
        self.w.redis_node_type = CacheNodeType


class Rds:
    def __init__(self, w):
        self.w = w

    def describe_db_clusters(self, DBClusterIdentifier):
        members = [{"DBInstanceIdentifier": i, "IsClusterWriter": i == self.w.writer}
                   for i in ("warden-pg-fs-aurora-1", "warden-pg-fs-aurora-2")]
        return {"DBClusters": [{"Status": "available", "DBClusterMembers": members,
                                "TagList": [{"Key": "Project", "Value": "warden-fullstack"}]}]}

    def describe_db_instances(self, DBInstanceIdentifier):
        return {"DBInstances": [{"Endpoint": {"Address": DBInstanceIdentifier + ".x.rds.amazonaws.com"}}]}

    def failover_db_cluster(self, DBClusterIdentifier, TargetDBInstanceIdentifier):
        self.w.writer = TargetDBInstanceIdentifier


class Ecs:
    def __init__(self, w):
        self.w = w

    def describe_services(self, cluster, services, include=None):
        return {"services": [{"taskDefinition": self.w.ecs_td, "desiredCount": 2, "runningCount": 2,
                              "pendingCount": 0, "deployments": [{"rolloutState": "COMPLETED"}],
                              "tags": [{"key": "Project", "value": "warden-fullstack"}]}]}

    def describe_task_definition(self, taskDefinition):
        return {"taskDefinition": copy.deepcopy(self.w.tds[taskDefinition])}

    def register_task_definition(self, **spec):
        arn = f"{self.w.ecs_td.rsplit(':', 1)[0]}:{len(self.w.tds) + 3}"
        self.w.tds[arn] = copy.deepcopy(spec)
        return {"taskDefinition": {"taskDefinitionArn": arn}}

    def update_service(self, cluster, service, taskDefinition=None, forceNewDeployment=False):
        if taskDefinition:
            self.w.ecs_td = taskDefinition
        self.w.forced += bool(forceNewDeployment)


class Elb:
    def __init__(self, w):
        self.w = w

    def describe_target_groups(self, Names):
        return {"TargetGroups": [{"TargetGroupArn": "arn:aws:elasticloadbalancing:ap-south-2:111122223333:targetgroup/warden-pg-fs-orders/abc",
                                  "HealthCheckPath": self.w.tg_path}]}

    def describe_tags(self, ResourceArns):
        return {"TagDescriptions": [{"Tags": [{"Key": "Project", "Value": "warden-fullstack"}]}]}

    def modify_target_group(self, TargetGroupArn, HealthCheckPath):
        self.w.tg_path = HealthCheckPath

    def describe_target_health(self, TargetGroupArn):
        state = "healthy" if self.w.tg_path == "/health" else "unhealthy"
        return {"TargetHealthDescriptions": [{"TargetHealth": {"State": state}}] * 2}


class Events:
    def __init__(self, w):
        self.w = w

    def describe_rule(self, Name):
        return {"State": self.w.rule, "Arn": "arn:aws:events:ap-south-2:111122223333:rule/" + Name}

    def list_tags_for_resource(self, ResourceARN):
        return {"Tags": [{"Key": "Project", "Value": "warden-fullstack"}]}

    def disable_rule(self, Name):
        self.w.rule = "DISABLED"

    def enable_rule(self, Name):
        self.w.rule = "ENABLED"


class Secrets:
    def __init__(self, w):
        self.w = w

    def describe_secret(self, SecretId):
        return {"Tags": [{"Key": "Project", "Value": "warden-fullstack"}]}

    def get_secret_value(self, SecretId):
        return {"SecretString": self.w.secret}

    def put_secret_value(self, SecretId, SecretString):
        self.w.secret = SecretString


class Core:
    def __init__(self, w):
        self.w = w

    def read_namespace(self, name):
        return {"metadata": {"labels": dict(self.w.ns_labels)}}

    def read_namespaced_config_map(self, name, namespace):
        return {"data": dict(self.w.configmap)}

    def patch_namespaced_config_map(self, name, namespace, body):
        assert body[0]["path"] == "/data"
        self.w.configmap = dict(body[0]["value"])

    def read_namespaced_secret(self, name, namespace):
        return {"data": dict(self.w.k8s_secret)}

    def patch_namespaced_secret(self, name, namespace, body):
        op = body[0]
        if op["op"] == "remove":
            self.w.k8s_secret.pop(op["path"].rsplit("/", 1)[-1])
        else:
            self.w.k8s_secret = dict(op["value"])


class Apps:
    def __init__(self, w):
        self.w = w

    def read_namespaced_deployment(self, name, namespace):
        dep = copy.deepcopy(self.w.deployments[name])
        # Ready only while the pod template is the baseline one (the fake's kubelet).
        baseline = World().deployments[name]["spec"]["template"]["spec"]["containers"]
        ready = dep["spec"]["replicas"] if dep["spec"]["template"]["spec"]["containers"] == baseline else 0
        dep["status"] = {"readyReplicas": ready, "updatedReplicas": dep["spec"]["replicas"]}
        return dep

    def patch_namespaced_deployment(self, name, namespace, body):
        dep = self.w.deployments[name]
        if isinstance(body, dict):  # a rollout restart annotation
            dep["spec"]["template"]["metadata"].update(body["spec"]["template"]["metadata"])
            return
        for op in body:
            parts = op["path"].strip("/").split("/")
            container = dep["spec"]["template"]["spec"]["containers"][int(parts[4])]
            if op["op"] == "remove":
                container.pop(parts[5])
            else:
                container[parts[5]] = copy.deepcopy(op["value"])


class Cw:
    def __init__(self, values=None):
        self.values = values or {}

    def get_metric_data(self, MetricDataQueries, **_kw):
        (q,) = MetricDataQueries
        v = self.values.get(q["MetricStat"]["Metric"]["MetricName"])
        return {"MetricDataResults": [{"Id": q["Id"], "Values": [] if v is None else [v]}]}


class Cur:
    def __init__(self, conn):
        self.conn, self.w, self.description, self._row = conn, conn.w, None, None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=()):
        w, s, self.description, self._row = self.w, " ".join(sql.split()), ("col",), None
        self.conn.log.append(s)
        if s == "SELECT current_database()":
            self._row = ("shop",)
        elif s.startswith("SELECT indexdef FROM pg_indexes"):
            d = w.indexes.get(params[0])
            self._row = (d,) if d else None
        elif s.startswith("DROP INDEX"):
            w.indexes.pop(s.rsplit(" ", 1)[-1].strip('"'), None)
            self.description = None
        elif s.startswith("CREATE INDEX CONCURRENTLY IF NOT EXISTS"):
            name = s.split()[6]
            w.indexes.setdefault(name, s.replace("CONCURRENTLY IF NOT EXISTS ", ""))
            self.description = None
        elif "count(pg_terminate_backend" in s:
            n = w.held_apps.count(params[0])
            w.held_apps = [a for a in w.held_apps if a != params[0]]
            self._row = (n,)
        elif "application_name LIKE" in s:
            self._row = (len(w.held_apps),)
        elif "application_name = %s" in s:
            self._row = (w.held_apps.count(params[0]),)
        elif s.startswith("SELECT to_regclass"):
            self._row = (params[0] if params[0] in w.indexes else None,)
        else:
            self._row = (0,)

    def fetchone(self):
        return self._row

    def fetchall(self):
        return [self._row] if self._row else []


class Conn:
    def __init__(self, w, log):
        self.w, self.log, self.closed = w, log, False

    def cursor(self):
        return Cur(self)

    def close(self):
        self.closed = True


def make(w: World | None = None, cw: dict | None = None):
    w = w or World()
    log: list[str] = []
    c = fs.Clients(lam=Lam(w), sqs=Sqs(w), ddb=Ddb(w), ec2=Ec2(w), rds=Rds(w), ecs=Ecs(w), ec=ElastiCache(w),
                   elbv2=Elb(w), iam=Iam(w), events=Events(w), secrets=Secrets(w), cw=Cw(cw),
                   apps=Apps(w), core=Core(w), sql=lambda **kw: Conn(w, log),
                   sql_reader=lambda **kw: Conn(w, log))
    t = fs.Target(writer_endpoint="warden-pg-fs-aurora.cluster-x.rds.amazonaws.com",
                  reader_endpoint="warden-pg-fs-aurora.cluster-ro-x.rds.amazonaws.com",
                  redis_sg_id="sg-redis", ecs_baseline_td=w.ecs_td, sleep=lambda _s: None)

    def spawn(fid):
        w.held_apps += [fs.HOLD_APP_PREFIX + fid] * 3
        return 4242

    t.spawn_holder, t.wait_holder_ready = spawn, lambda fid, _t: {"ok": True, "held": 3}
    t.stop_holder = lambda fid: None
    return w, c, t


# =========================================================================== inject / revert


INJECTED = [fid for fid in fs.FAULTS if fid != "fs-00"]


@pytest.mark.parametrize("fid", INJECTED)
def test_every_inject_changes_state_and_its_revert_restores_it_exactly(fid):
    w, c, t = make()
    before = w.snapshot()
    fs.FAULTS[fid].inject(c, t)
    assert w.snapshot() != before, f"{fid} injected nothing"
    fs.FAULTS[fid].revert(c, t)
    assert w.snapshot() == before, f"{fid}: the revert did not restore the exact prior state"
    assert fid not in t.saved


@pytest.mark.parametrize("fid", INJECTED)
def test_every_revert_is_idempotent(fid):
    w, c, t = make()
    before = w.snapshot()
    fs.FAULTS[fid].inject(c, t)
    fs.FAULTS[fid].revert(c, t)
    fs.FAULTS[fid].revert(c, t)
    assert w.snapshot() == before


@pytest.mark.parametrize("fid", INJECTED)
def test_the_prior_state_is_persisted_before_the_first_write(fid):
    """Inject and revert run in different processes. If the capture is not on disk before the
    first write, a crash in between leaves a broken stack and no way back."""
    w, c, t = make()
    persisted: list[str] = []
    t.persist = lambda f: persisted.append(f) if f in t.saved else None
    snap = w.snapshot()
    real_patch = {}

    def spy(obj, name):
        fn = getattr(obj, name)

        def wrapped(*a, **kw):
            real_patch.setdefault("first_write_persisted", bool(persisted))
            return fn(*a, **kw)
        setattr(obj, name, wrapped)

    for obj, names in ((c.lam, ("update_function_configuration", "put_function_concurrency",
                                "update_event_source_mapping", "invoke")),
                       (c.iam, ("put_role_policy", "delete_role_policy")), (c.sqs, ("send_message", "set_queue_attributes")),
                       (c.ddb, ("update_table",)), (c.ec2, ("revoke_security_group_ingress",)),
                       (c.ecs, ("register_task_definition",)), (c.elbv2, ("modify_target_group",)),
                       (c.events, ("disable_rule",)), (c.secrets, ("put_secret_value",)),
                       (c.core, ("patch_namespaced_config_map", "patch_namespaced_secret")),
                       (c.apps, ("patch_namespaced_deployment",))):
        for name in names:
            spy(obj, name)
    fs.FAULTS[fid].inject(c, t)
    if fid in ("fs-12", "fs-13", "fs-16"):  # SQL/holder faults: saved before the session opens
        assert persisted and persisted[0] == fid
    else:
        assert real_patch.get("first_write_persisted") is True, fid
    assert w.snapshot() != snap


def test_a_revert_with_nothing_saved_touches_nothing():
    w, c, t = make()
    before = w.snapshot()
    for fid in INJECTED:
        fs.FAULTS[fid].revert(c, t)
    assert w.snapshot() == before


def test_checkout_config_faults_are_real_deploys_on_the_alias():
    w, c, t = make()
    fs.FAULTS["fs-02"].inject(c, t)
    live = w.versions[w.alias["warden-pg-fs-checkout"]]
    assert w.alias["warden-pg-fs-checkout"] != "7"
    assert live["Timeout"] == 1
    assert live["Environment"]["Variables"]["DDB_EXTRA_LATENCY_MS"] == "2000"


def test_failover_records_the_original_writer_and_fails_back():
    w, c, t = make()
    fs.FAULTS["fs-15"].inject(c, t)
    assert w.writer == "warden-pg-fs-aurora-2"
    assert w.lambdas["warden-pg-fs-order-processor"]["Environment"]["Variables"]["DB_HOST"].startswith(
        "warden-pg-fs-aurora-1.")
    fs.FAULTS["fs-15"].revert(c, t)
    assert w.writer == "warden-pg-fs-aurora-1"


def test_iam_auth_revoke_removes_the_task_roles_db_login_and_the_revert_puts_it_back():
    """fs-21 (db_iam_auth_revoked): the task role's only policy grants only rds-db:connect, so the
    policy goes (IAM refuses an empty one); a deployment is forced both ways."""
    w, c, t = make()
    before = copy.deepcopy(w.iam["warden-pg-fs-orders-api-task"])
    assert fs.check_baseline(c, t, ["ecs"]) == []
    fs.FAULTS["fs-21"].inject(c, t)
    assert w.iam["warden-pg-fs-orders-api-task"] == {} and w.forced == 1
    assert "warden-pg-fs-orders-api-task no longer grants rds-db:connect" in fs.check_baseline(c, t, ["ecs"])
    assert w.iam["warden-pg-fs-ecs-exec"], "the execution role is fs-18's, not this fault's"
    fs.FAULTS["fs-21"].revert(c, t)
    assert w.iam["warden-pg-fs-orders-api-task"] == before and w.forced == 2
    assert "fs-21" not in t.saved


def test_an_iam_revert_removes_the_policy_a_fix_added():
    """WARDEN's fix puts its OWN policy (warden-restore-*); after the revert re-puts the original,
    the role must hold exactly what it held before the inject - not both."""
    w, c, t = make()
    before = copy.deepcopy(w.iam)
    fs.FAULTS["fs-21"].inject(c, t)
    w.iam["warden-pg-fs-orders-api-task"]["warden-restore-rds-db-connect"] = {"Statement": [{"Action": "rds-db:connect"}]}
    out = fs.FAULTS["fs-21"].revert(c, t)
    assert out["removed_extra"] == ["warden-restore-rds-db-connect"]
    assert w.iam == before


def test_an_empty_db_host_is_the_processors_baseline():
    """Terraform cannot know the Aurora endpoints (express configuration): DB_HOST "" means the code
    uses the metadata secret's host. fs-14 / fs-15 set it; their reverts put "" back."""
    w, c, t = make()
    w.lambdas["warden-pg-fs-order-processor"]["Environment"]["Variables"]["DB_HOST"] = ""
    assert fs.check_baseline(c, t, ["processor"]) == []
    fs.FAULTS["fs-14"].inject(c, t)
    assert fs.check_baseline(c, t, ["processor"])
    fs.FAULTS["fs-14"].revert(c, t)
    assert w.lambdas["warden-pg-fs-order-processor"]["Environment"]["Variables"]["DB_HOST"] == ""


def test_the_slow_query_index_is_recreated_concurrently_from_its_own_definition():
    w, c, t = make()
    log: list[str] = []
    c.sql = lambda **kw: Conn(w, log)
    fs.FAULTS["fs-16"].inject(c, t)
    assert "orders_customer_id_idx" not in w.indexes
    fs.FAULTS["fs-16"].revert(c, t)
    assert any(s.startswith("CREATE INDEX CONCURRENTLY IF NOT EXISTS orders_customer_id_idx ON public.orders")
               for s in log)


def test_held_sessions_are_terminated_by_application_name_on_revert():
    w, c, t = make()
    fs.FAULTS["fs-13"].inject(c, t)
    assert w.held_apps == ["warden-bench-hold-fs-13"] * 3
    fs.FAULTS["fs-13"].revert(c, t)
    assert w.held_apps == []


def test_a_revert_that_leaves_held_sessions_open_fails_loudly():
    w, c, t = make()
    fs.FAULTS["fs-12"].inject(c, t)
    real_sql = c.sql

    class Stubborn(Conn):
        def cursor(self):
            cur = Cur(self)
            orig = cur.execute

            def execute(sql, params=()):
                if "pg_terminate_backend" in sql:
                    cur._row, cur.description = (0,), ("c",)
                    return
                orig(sql, params)
            cur.execute = execute
            return cur

    c.sql = lambda **kw: Stubborn(w, [])
    with pytest.raises(OpError, match="still open"):
        fs.FAULTS["fs-12"].revert(c, t)
    c.sql = real_sql


def test_the_redis_filler_goes_through_the_ops_lambda_and_is_flushed():
    w, c, t = make()
    fs.FAULTS["fs-11"].inject(c, t)
    assert w.redis_used == 10 + t.redis_fill_mb
    ok, _ = fs.FAULTS["fs-11"].verify(c, t)
    assert not ok
    fs.FAULTS["fs-11"].revert(c, t)
    assert fs.FAULTS["fs-11"].verify(c, t)[0]


# =========================================================================== the guard


def test_an_untagged_lambda_is_refused():
    w, c, t = make()
    w.tags["warden-pg-fs-checkout"] = {}
    with pytest.raises(OpError, match="not tagged"):
        fs.FAULTS["fs-03"].inject(c, t)
    assert w.concurrency == {}


def test_a_lambda_tagged_for_another_project_is_refused():
    w, c, t = make()
    w.tags["warden-pg-fs-checkout"] = {"Project": "warden-proving-ground"}
    with pytest.raises(OpError):
        fs.FAULTS["fs-01"].inject(c, t)
    assert w.alias["warden-pg-fs-checkout"] == "7"


def test_an_unprefixed_resource_is_refused_even_when_tagged():
    w, c, t = make()
    t.checkout = "checkout"
    w.lambdas["checkout"] = copy.deepcopy(w.lambdas["warden-pg-fs-checkout"])
    w.lambdas["checkout"]["FunctionArn"] = "arn:aws:lambda:ap-south-2:111122223333:function:checkout"
    w.tags["checkout"] = dict(TAGGED)
    with pytest.raises(OpError, match="not named"):
        fs.FAULTS["fs-03"].inject(c, t)


def test_an_unprefixed_security_group_is_refused():
    w, c, t = make()
    w.sg_name = "default"
    with pytest.raises(OpError, match="not named"):
        fs.FAULTS["fs-10"].inject(c, t)
    assert w.sg_rules


def test_an_unlabelled_namespace_is_refused():
    w, c, t = make()
    w.ns_labels = {}
    for fid in ("fs-22", "fs-23", "fs-24", "fs-25", "fs-26"):
        with pytest.raises(OpError, match="not labelled"):
            fs.FAULTS[fid].inject(c, t)
    assert w.snapshot()["configmap"] == World().configmap


def test_the_database_guard_refuses_a_foreign_endpoint():
    w, c, t = make()
    t.writer_endpoint = "prod-db.cluster-x.rds.amazonaws.com"
    with pytest.raises(OpError, match="not the"):
        fs.FAULTS["fs-16"].inject(c, t)
    assert "orders_customer_id_idx" in w.indexes


def test_a_guard_that_cannot_read_tags_refuses():
    w, c, t = make()

    def boom(**_kw):
        raise Err("AccessDenied")
    c.events.list_tags_for_resource = boom
    with pytest.raises(OpError, match="cannot read the tags"):
        fs.FAULTS["fs-27"].inject(c, t)
    assert w.rule == "ENABLED"


# =========================================================================== baseline + verify


def test_a_clean_stack_is_at_baseline_and_each_fault_breaks_its_area():
    for fid in INJECTED:
        _w, c, t = make()
        assert fs.check_baseline(c, t) == [], fid
        fs.FAULTS[fid].inject(c, t)
        if fid not in ("fs-06", "fs-12", "fs-13"):  # visible only through traffic / sessions
            assert fs.check_baseline(c, t, [fs.FAULTS[fid].area]), f"{fid} is invisible to its baseline"


def test_an_unreadable_component_is_a_problem_not_a_pass():
    _w, c, t = make()
    c.events = None
    assert any(p.startswith("rule: cannot check") for p in fs.check_baseline(c, t))


def test_lambda_verifier_needs_real_invocations_and_no_errors():
    _w, c, t = make(cw={"Errors": 0, "Throttles": 0, "Invocations": 12})
    assert fs.checkout_clean(c, t)[0]
    _w, c, t = make(cw={"Errors": 0, "Throttles": 0})
    assert not fs.checkout_clean(c, t)[0], "no invocations is not 'fixed'"
    _w, c, t = make(cw={"Errors": 2, "Invocations": 12})
    assert not fs.checkout_clean(c, t)[0]


# =========================================================================== the allow-list

S = "shell"
R = "--region ap-south-2"

ALLOWED = [
    f"aws lambda update-alias --function-name warden-pg-fs-checkout --name live --function-version 7 {R}",
    f"aws lambda put-function-concurrency --function-name warden-pg-fs-checkout --reserved-concurrent-executions 50 {R}",
    f"aws lambda update-function-configuration --function-name warden-pg-fs-checkout --timeout 10 {R}",
    f"aws lambda update-function-configuration --function-name warden-pg-fs-order-processor --environment Variables={{DB_HOST=warden-pg-fs-aurora.cluster-x.rds.amazonaws.com}} {R}",
    f"aws lambda update-event-source-mapping --uuid uuid-orders --enabled {R}",
    f"aws dynamodb update-table --table-name warden-pg-fs-carts --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 {R}",
    f"aws ecs update-service --cluster warden-pg-fs-ecs --service warden-pg-fs-orders-api --force-new-deployment {R}",
    f"aws ecs update-service --cluster warden-pg-fs-ecs --service warden-pg-fs-orders-api --task-definition warden-pg-fs-orders-api:3 {R}",
    f"aws elbv2 modify-target-group --target-group-arn arn:aws:elasticloadbalancing:ap-south-2:111122223333:targetgroup/warden-pg-fs-orders/abc --health-check-path /health {R}",
    f"aws events enable-rule --name warden-pg-fs-reconcile-5m {R}",
    f"aws sqs set-queue-attributes --queue-url https://sqs.ap-south-2.amazonaws.com/111122223333/warden-pg-fs-notifications --attributes file-free {R}",
    f"aws sqs start-message-move-task --source-arn arn:aws:sqs:ap-south-2:111122223333:warden-pg-fs-orders-dlq {R}",
    f"aws rds failover-db-cluster --db-cluster-identifier warden-pg-fs-aurora --target-db-instance-identifier warden-pg-fs-aurora-1 {R}",
    f"aws ec2 authorize-security-group-ingress --group-id sg-redis --protocol tcp --port 6379 --source-group sg-app1 {R}",
    "aws --region ap-south-2 events enable-rule --name warden-pg-fs-reconcile-5m",
    "aws --region=ap-south-2 lambda update-alias --function-name warden-pg-fs-checkout --name live --function-version 7",
    "kubectl -n shop rollout undo deployment/catalog-api",
    "kubectl -n shop rollout restart deployment catalog-api",
    "kubectl --namespace shop set image deployment/catalog-api catalog-api=ecr/app:v1",
    "kubectl --namespace=shop set resources deployment/cart-worker --requests=cpu=100m",
    "kubectl -n shop scale deployment/catalog-api --replicas=2",
    "kubectl -n shop patch configmap catalog-config --type merge -p '{\"data\":{\"CATALOG_PAGE_SIZE\":\"20\"}}'",
    "kubectl -n shop apply -f -\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: catalog-config\ndata:\n  CATALOG_PAGE_SIZE: \"20\"\n",
]
IAM_OK = ("aws iam put-role-policy --role-name warden-pg-fs-checkout --policy-name inline "
          "--policy-document '" + json.dumps({"Version": "2012-10-17", "Statement": [{
              "Effect": "Allow", "Action": ["dynamodb:PutItem"],
              "Resource": "arn:aws:dynamodb:ap-south-2:111122223333:table/warden-pg-fs-carts"}]}) + f"' {R}")



def _db_grant(role: str, resource: str, action: str = "rds-db:connect") -> str:
    doc = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": action,
                                                              "Resource": resource}]}, separators=(",", ":"))
    return f"aws iam put-role-policy --role-name {role} --policy-name warden-restore-rds-db-connect --policy-document '{doc}' {R}"


# fs-21's fix: rds-db:connect is scoped by DATABASE USER (the cluster id in the ARN is masked: `*`).
DB_GRANT_OK = _db_grant("warden-pg-fs-orders-api-task", "arn:aws:rds-db:ap-south-2:*:dbuser:*/app")

STACK_IDS = frozenset({"uuid-orders", "sg-redis", "sg-app1"})

REJECTED = [
    # shell injection, in every shape
    (f"aws events enable-rule --name warden-pg-fs-reconcile-5m {R}; rm -rf /", "metacharacter"),
    (f"aws events enable-rule --name warden-pg-fs-reconcile-5m {R} && curl evil", "metacharacter"),
    (f"aws events enable-rule --name warden-pg-fs-reconcile-5m {R} | sh", "metacharacter"),
    (f"aws events enable-rule --name $(whoami) {R}", "not an aws read"),
    (f"aws events enable-rule --name `id` {R}", "metacharacter"),
    (f"aws events enable-rule --name warden-pg-fs-x {R} > /tmp/x", "metacharacter"),
    (f"aws events enable-rule --name warden-pg-fs-x {R} < /etc/passwd", "metacharacter"),
    (f"aws events enable-rule --name warden-pg-fs-x {R}\naws iam create-user --user-name x", "metacharacter"),
    (f"aws lambda update-function-configuration --function-name warden-pg-fs-checkout --environment Variables={{A=$HOME}} {R}", "metacharacter"),
    # delete / not a listed verb / not a listed service
    (f"aws dynamodb delete-table --table-name warden-pg-fs-carts {R}", "delete"),
    (f"aws lambda delete-function-concurrency --function-name warden-pg-fs-checkout {R}", "delete"),
    (f"aws s3 rm s3://warden-pg-fs-bucket --recursive {R}", "not an allowed"),
    (f"aws iam create-access-key --user-name warden-pg-fs-x {R}", "not an allowed"),
    (f"aws iam attach-role-policy --role-name warden-pg-fs-checkout --policy-arn arn:aws:iam::aws:policy/AdministratorAccess {R}", "not an allowed"),
    (f"aws lambda invoke --function-name warden-pg-fs-ops out.json {R}", "not an allowed"),
    (f"aws rds reboot-db-instance --db-instance-identifier warden-pg-fs-aurora-1 {R}", "not an allowed"),
    # outside the stack
    (f"aws events enable-rule --name prod-reconcile {R}", "not a warden-pg-fs-"),
    (f"aws lambda update-alias --function-name checkout --name live --function-version 3 {R}", "not a warden-pg-fs-"),
    (f"aws lambda update-alias --function-name arn:aws:lambda:ap-south-2:111122223333:function:prod-checkout --name live --function-version 3 {R}", "not a warden-pg-fs-"),
    (f"aws ec2 authorize-security-group-ingress --group-id sg-prod --protocol tcp --port 22 {R}", "not a warden-pg-fs-"),
    (f"aws ec2 authorize-security-group-ingress --group-id sg-redis --protocol tcp --port 6379 --cidr 0.0.0.0/0 {R}", "internet"),
    (f"aws lambda update-event-source-mapping --uuid not-ours --enabled {R}", "not a warden-pg-fs-"),
    (f"aws sqs set-queue-attributes --queue-url https://sqs.ap-south-2.amazonaws.com/111122223333/prod-q --attributes x {R}", "not a warden-pg-fs-"),
    (f"aws ecs update-service --cluster warden-pg-fs-ecs --service warden-pg-fs-orders-api --task-definition arn:aws:ecs:ap-south-2:111122223333:task-definition/prod-api:1 {R}", "not a warden-pg-fs-"),
    (f"aws lambda update-function-configuration --function-name warden-pg-fs-checkout --role arn:aws:iam::111122223333:role/admin {R}", "not a warden-pg-fs-"),
    (f"aws dynamodb update-table --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 {R}", "names no"),
    # region and credential tricks
    ("aws events enable-rule --name warden-pg-fs-reconcile-5m", "--region"),
    ("aws events enable-rule --name warden-pg-fs-reconcile-5m --region us-east-1", "--region"),
    (f"aws events enable-rule --name warden-pg-fs-reconcile-5m {R} --region us-east-1", "--region"),
    (f"aws events enable-rule --name warden-pg-fs-reconcile-5m {R} --profile admin", "--profile"),
    (f"aws events enable-rule --name warden-pg-fs-reconcile-5m {R} --endpoint-url http://evil", "--endpoint-url"),
    (f"aws lambda update-function-configuration --function-name warden-pg-fs-checkout --cli-input-json file://x.json {R}", "--cli-input-json"),
    (f"aws iam put-role-policy --role-name warden-pg-fs-checkout --policy-name p --policy-document file://p.json {R}", "local file"),
    # IAM beyond one warden-pg-fs role's inline policy
    (f"aws iam put-role-policy --role-name admin --policy-name p --policy-document '{{}}' {R}", "not a warden-pg-fs-"),
    ("aws iam put-role-policy --role-name warden-pg-fs-checkout --policy-name p --policy-document '"
     + json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}) + f"' {R}", "wildcard"),
    ("aws iam put-role-policy --role-name warden-pg-fs-checkout --policy-name p --policy-document '"
     + json.dumps({"Statement": [{"Effect": "Allow", "Action": "iam:PassRole",
                                  "Resource": "arn:aws:iam::111122223333:role/warden-pg-fs-x"}]}) + f"' {R}", "IAM action"),
    ("aws iam put-role-policy --role-name warden-pg-fs-checkout --policy-name p --policy-document '"
     + json.dumps({"Statement": [{"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": "*"}]}) + f"' {R}", "not a stack resource"),
    # a database login: only the application users, only rds-db:connect, only this region
    (_db_grant("warden-pg-fs-orders-api-task", "arn:aws:rds-db:ap-south-2:*:dbuser:*/postgres"), "outside the stack"),
    (_db_grant("warden-pg-fs-orders-api-task", "arn:aws:rds-db:ap-south-2:*:dbuser:*/warden_ro"), "outside the stack"),
    (_db_grant("warden-pg-fs-orders-api-task", "arn:aws:rds-db:ap-south-2:*:dbuser:*/*"), "outside the stack"),
    (_db_grant("warden-pg-fs-orders-api-task", "arn:aws:rds-db:us-east-1:*:dbuser:*/app"), "outside the stack"),
    (_db_grant("warden-pg-fs-orders-api-task", "arn:aws:rds-db:ap-south-2:*:dbuser:*/app", "rds:DeleteDBCluster"),
     "only be granted rds-db:connect"),
    (_db_grant("admin", "arn:aws:rds-db:ap-south-2:*:dbuser:*/app"), "not a warden-pg-fs-"),
    # other programs
    ("bash -c 'aws events enable-rule'", "not an allowed program"),
    ("curl http://169.254.169.254/latest/meta-data/", "not an allowed program"),
    ("python -c 'import os'", "not an allowed program"),
    ("", "empty"),
    # kubectl
    ("kubectl rollout undo deployment/catalog-api", "-n shop"),
    ("kubectl -n kube-system rollout restart deployment/coredns", "-n shop"),
    ("kubectl -n shop -n kube-system scale deployment/x --replicas=0", "-n shop"),
    ("kubectl -n shop delete pod catalog-api-abc", "not allowed"),
    ("kubectl -n shop exec catalog-api-abc -- sh", "not allowed"),
    ("kubectl -n shop rollout status deployment/catalog-api", "undo and restart"),
    ("kubectl -n shop patch rolebinding warden --type json -p '[]'", "not allowed"),
    ("kubectl -n shop set serviceaccount deployment/catalog-api admin", "set: only"),
    ("kubectl -n shop scale deployment/x --replicas=1 --kubeconfig /root/.kube/config", "--kubeconfig"),
    ("kubectl -n shop scale deployment/x --replicas=1 --context prod", "--context"),
    ("kubectl -n shop scale deployment/x --replicas=1 --all-namespaces", "--all-namespaces"),
    ("kubectl -n shop scale deployment/x --replicas=1 --as system:admin", "--as"),
    ("kubectl -n shop apply -f https://evil/x.yaml", "apply -f -"),
    ("kubectl -n shop apply -f -\napiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: x\n", "kind"),
    ("kubectl -n shop apply -f -\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n  namespace: kube-system\n", "namespace"),
]

SQL_OK = [
    "SELECT pg_terminate_backend(4242)",
    "SELECT pg_cancel_backend(4242);",
    "select pg_terminate_backend(pid) from pg_stat_activity where state = 'idle in transaction'",
    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = 'x' AND now() - state_change > interval '5 minutes'",
    "CREATE INDEX CONCURRENTLY orders_customer_id_idx ON orders (customer_id)",
    "CREATE INDEX CONCURRENTLY IF NOT EXISTS orders_customer_id_idx ON public.orders USING btree (customer_id)",
    "ALTER DATABASE shop SET idle_in_transaction_session_timeout = '60s'",
    "ALTER DATABASE shop SET statement_timeout TO 30000",
]
SQL_BAD = [
    "SELECT pg_terminate_backend(4242); DROP TABLE orders",
    "DROP TABLE orders",
    "DELETE FROM orders",
    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid IN (SELECT pid FROM pg_locks)",
    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE 1=1 -- all of them",
    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = current_user /* x */",
    "SELECT pg_terminate_backend(pid)",
    "SELECT pg_read_file('/etc/passwd')",
    "CREATE INDEX orders_x ON orders (customer_id)",
    "ALTER DATABASE shop SET session_preload_libraries = 'evil'",
    "ALTER ROLE shop_app SUPERUSER",
    "ALTER DATABASE shop OWNER TO attacker",
    "GRANT ALL ON orders TO public",
    "COPY orders TO PROGRAM 'curl evil'",
]


@pytest.mark.parametrize("command", [*ALLOWED, IAM_OK, DB_GRANT_OK,
                                     _db_grant("warden-pg-fs-catalog-pod", "arn:aws:rds-db:ap-south-2:*:dbuser:*/catalog")])
def test_allowed_fix_commands(command):
    reason = fs.check_command({"kind": S, "command": command},
                              stack_ids=STACK_IDS)
    assert reason is None, reason


@pytest.mark.parametrize("command,why", REJECTED)
def test_rejected_fix_commands(command, why):
    reason = fs.check_command({"kind": S, "command": command},
                              stack_ids=STACK_IDS)
    assert reason is not None, f"ALLOWED: {command!r}"
    assert why.lower() in reason.lower(), reason


@pytest.mark.parametrize("sql", SQL_OK)
def test_allowed_sql(sql):
    assert fs.check_command({"kind": "sql", "command": sql, "target": "writer"}) is None


@pytest.mark.parametrize("sql", SQL_BAD)
def test_rejected_sql(sql):
    assert fs.check_command({"kind": "sql", "command": sql, "target": "writer"}) is not None, sql


def test_sql_only_runs_on_the_writer():
    assert "writer" in fs.check_command({"kind": "sql", "command": SQL_OK[0], "target": "reader"})


def test_an_unknown_command_kind_is_refused():
    assert fs.check_command({"kind": "python", "command": "print(1)"})


# =========================================================================== deciding + running a fix


def test_a_rejected_verdict_blocks_the_fix_whatever_it_prints():
    built = {"fix_commands": [{"kind": S, "command": ALLOWED[0]}]}
    assert fs.decide_fix(built, "rejected") == ("blocked_by_gate", [], [])


@pytest.mark.parametrize("status", ["approved_for_human", "auto_safe", "escalated"])
def test_no_command_is_no_fix_printed(status):
    assert fs.decide_fix({"fix_commands": []}, status)[0] == "no_fix_printed"
    assert fs.decide_fix(None, status)[0] == "no_fix_printed"


def test_one_bad_command_means_nothing_runs():
    built = {"fix_commands": [{"kind": S, "command": ALLOWED[0]},
                              {"kind": S, "command": "kubectl -n shop delete deploy catalog-api"}]}
    outcome, run, rejected = fs.decide_fix(built, "approved_for_human")
    assert outcome == "fix_not_allowed" and run == []
    assert rejected[0]["command"].startswith("kubectl") and rejected[0]["reason"]


def test_allowed_commands_run_verbatim_without_a_shell():
    calls = []

    def run(argv, **kw):
        calls.append((argv, kw))

        class P:
            returncode, stdout, stderr = 0, "ok", ""
        return P()

    cmds = [{"kind": S, "command": ALLOWED[0]}, {"kind": S, "command": ALLOWED[-1]}]
    results, effects = fs.execute_fix(cmds, sql=None, run=run, which=lambda exe: f"C:/bin/{exe}.exe")
    assert [r["rc"] for r in results] == [0, 0] and effects == []
    argv, kw = calls[0]
    assert argv[0] == "C:/bin/aws.exe" and argv[1:4] == ["lambda", "update-alias", "--function-name"]
    assert kw["shell"] is False
    assert calls[1][1]["input"].startswith("apiVersion: v1"), "apply -f - gets the manifest on stdin"


def test_execution_stops_at_the_first_failure():
    def run(argv, **kw):
        class P:
            returncode, stdout, stderr = 1, "", "denied"
        return P()

    results, _ = fs.execute_fix([{"kind": S, "command": ALLOWED[0]}, {"kind": S, "command": ALLOWED[1]}],
                                sql=None, run=run, which=lambda e: e)
    assert len(results) == 1 and results[0]["stderr_tail"] == "denied"


def test_sql_fix_side_effects_are_recorded_and_undone():
    w, _c, _t = make()
    log: list[str] = []
    sql = lambda **kw: Conn(w, log)
    results, effects = fs.execute_fix(
        [{"kind": "sql", "command": "CREATE INDEX CONCURRENTLY new_idx ON orders (x)"},
         {"kind": "sql", "command": "ALTER DATABASE shop SET statement_timeout = '5s'"}], sql=sql)
    assert [r["rc"] for r in results] == [0, 0]
    assert {e["kind"] for e in effects} == {"index", "setting"}
    fs.undo_fix_effects(effects, sql)
    assert "DROP INDEX CONCURRENTLY IF EXISTS \"new_idx\"" in log
    assert "ALTER DATABASE \"shop\" RESET statement_timeout" in log


def test_this_module_does_not_import_the_tool_under_test():
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(fs))
    names = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
    names += [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    assert not [n for n in names if n.split(".")[0] == "warden"]



def test_fs10_revert_also_removes_a_rule_the_fix_added():
    """WARDEN's fix authorises every application SG it read - possibly one that never had a rule.
    The revert must leave the EXACT prior rule set, or every later fault runs on a wider network."""
    w, c, t = make()
    before = copy.deepcopy(w.sg_rules)
    fs.FAULTS["fs-10"].inject(c, t)
    w.sg_rules.append({"IpProtocol": "tcp", "FromPort": 6379, "ToPort": 6379,
                       "UserIdGroupPairs": [{"GroupId": "sg-extra"}]})     # what a fix added
    fs.FAULTS["fs-10"].revert(c, t)
    assert fs._group_pairs(w.sg_rules) == fs._group_pairs(before)


def test_fs11_revert_puts_the_original_node_type_back():
    """WARDEN's fix for memory pressure is a bigger node; the revert must restore the size."""
    w, c, t = make()
    fs.FAULTS["fs-11"].inject(c, t)
    w.redis_node_type = "cache.t4g.small"                                   # what the fix did
    out = fs.FAULTS["fs-11"].revert(c, t)
    assert w.redis_node_type == "cache.t4g.micro" and out["node_type_restored"]


def test_fs11_revert_refuses_while_a_resize_is_still_running():
    w, c, t = make()
    fs.FAULTS["fs-11"].inject(c, t)
    w.redis_node_type, w.redis_status = "cache.t4g.small", "modifying"
    with pytest.raises(fs.OpError, match="still 'modifying'"):
        fs.FAULTS["fs-11"].revert(c, t)
    assert "fs-11" in t.saved                                              # can be run again


# --------------------------------------------------------------------------- fs-12 holder, as measured


class _LimitedServer:
    """A server that accepts `limit` held sessions, then refuses - from any thread."""

    def __init__(self, max_connections: int, limit: int):
        import threading
        self.max_connections, self.limit, self.open = max_connections, limit, 0
        self.lock = threading.Lock()

    def sql(self, **kw):
        server = self

        class _Cur:
            description = ("col",)

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def execute(self, *a):
                pass

            def fetchone(self):
                return (str(server.max_connections),)

        class _Conn:
            def cursor(self):
                return _Cur()

            def close(self):
                if kw.get("application_name"):
                    with server.lock:
                        server.open -= 1

        if kw.get("application_name"):
            with server.lock:
                if self.open >= self.limit:
                    raise RuntimeError("FATAL: remaining connection slots are reserved")
                self.open += 1
        return _Conn()


def test_fs12_holds_until_the_server_refuses_not_until_its_own_count():
    # The server's real ceiling (40) is below max_connections (50): reserved slots, other users.
    # Stopping at max_connections would never be refused; the holder must push until it is.
    server = _LimitedServer(max_connections=50, limit=40)
    c = fs.Clients(**{**{f: None for f in fs.Clients.__dataclass_fields__}, "sql": server.sql})
    held, info = fs.hold_connections(c, None, "fs-12", headroom=3, workers=8)
    assert info["held"] == len(held) == 37 == server.open
    assert info["refused"] == 50 + 50 - 40 and info["stopped_by"] == "RuntimeError"


def test_fs12_revert_waits_out_backends_that_are_still_exiting(monkeypatch):
    _w, c, t = make()
    counts = iter([2, 1, 0])  # terminated backends leave pg_stat_activity a moment later
    monkeypatch.setattr(fs, "_terminate_holders", lambda c, fid: 0)
    monkeypatch.setattr(fs, "_holders_left", lambda c, fid: next(counts))
    t.saved["fs-12"] = {"app_name": fs.HOLD_APP_PREFIX + "fs-12"}
    fs._revert_held(c, t, "fs-12")
    assert "fs-12" not in t.saved


def test_fs12_revert_still_fails_loudly_when_sessions_never_go(monkeypatch):
    _w, c, t = make()
    monkeypatch.setattr(fs, "_terminate_holders", lambda c, fid: 0)
    monkeypatch.setattr(fs, "_holders_left", lambda c, fid: 2)
    t.saved["fs-12"] = {"app_name": fs.HOLD_APP_PREFIX + "fs-12"}
    with pytest.raises(fs.OpError, match="2 held session"):
        fs._revert_held(c, t, "fs-12", attempts=3)
    assert "fs-12" in t.saved  # nothing marked done: a later revert can still end them

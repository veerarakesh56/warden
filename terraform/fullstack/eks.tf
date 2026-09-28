# EKS for the `shop` namespace. The cluster and node group only: every Kubernetes object (shop,
# Deployments, ConfigMap, Secret, the warden ServiceAccount) is applied by the APPS pipeline from
# k8s/fullstack/.
#
# Lessons carried over from terraform/proving-ground/eks.tf (Wave 2, measured):
#  - endpoint_private_access MUST be true while the public endpoint is locked to one IP, or nodes
#    reach the API from their own public IPs, are refused, and never join (~20 billed minutes).
#  - on a fresh account create the node-group service-linked role FIRST (README): CreateNodegroup
#    checks it with the caller's credentials against a path-less ARN the boundary does not match.
#  - service-linked roles are not terraform resources: the operator cannot delete them, so owning
#    them here would fail every destroy.

resource "aws_iam_role" "eks_cluster" {
  name                 = "${local.name}-eks-cluster"
  permissions_boundary = local.permissions_boundary
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "eks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_eks_cluster" "this" {
  name     = "${local.name}-eks"
  version  = var.kubernetes_version
  role_arn = aws_iam_role.eks_cluster.arn

  vpc_config {
    subnet_ids              = aws_subnet.private[*].id
    endpoint_public_access  = true
    endpoint_private_access = true # ⛔ see the header
    public_access_cidrs     = coalesce(var.eks_public_access_cidrs, [local.my_ip_cidr])
  }

  access_config {
    authentication_mode = "API"
    # false: the admin entry is an explicit resource below, so it is visible, destroyable, and can
    # name more than one principal (the CI deploy role).
    bootstrap_cluster_creator_admin_permissions = false
  }

  upgrade_policy {
    support_type = "STANDARD" # never slide into extended support (0.60 USD/hour instead of 0.10)
  }

  depends_on = [aws_iam_role_policy_attachment.eks_cluster]
}

# Whoever runs terraform (the role behind an assumed-role session, not the session) plus any extra
# principals, as cluster admins.
data "aws_iam_session_context" "current" {
  arn = data.aws_caller_identity.current.arn
}

resource "aws_eks_access_entry" "admin" {
  for_each      = toset(concat([data.aws_iam_session_context.current.issuer_arn], var.eks_admin_principal_arns))
  cluster_name  = aws_eks_cluster.this.name
  principal_arn = each.value
}

resource "aws_eks_access_policy_association" "admin" {
  for_each      = aws_eks_access_entry.admin
  cluster_name  = aws_eks_cluster.this.name
  principal_arn = each.value.principal_arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  access_scope {
    type = "cluster"
  }
}

# --------------------------------------------------------------------------- nodes

resource "aws_iam_role" "eks_node" {
  name                 = "${local.name}-eks-node"
  permissions_boundary = local.permissions_boundary
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_node" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    # The CloudWatch observability add-on's agent runs on the node and publishes the pod metrics
    # the shop alarms read (alarms.tf).
    "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy",
  ])
  role       = aws_iam_role.eks_node.name
  policy_arn = each.value
}

# 1 x m7i-flex.large ON_DEMAND (2 vCPU, 8 GiB, 29 pods). Changed 2026-09-26 from t3.medium: the
# account is on the AWS Free plan, which refuses instance types that are not Free Tier eligible
# (in ap-south-2: t3/t4g/t8i micro+small, c7i-flex.large, m7i-flex.large). t3.small takes 11 pods,
# too few for system pods + shop + a rollout; m7i-flex.large is the eligible type with room.
# Still 2 vCPU, so fs-25 (8 CPU requested) stays unschedulable. Spot would add an unplanned second
# fault mid-run.
resource "aws_eks_node_group" "this" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "${local.name}-eks-ng"
  node_role_arn   = aws_iam_role.eks_node.arn
  subnet_ids      = aws_subnet.private[*].id # nodes have no public IP; egress through the NAT
  instance_types  = ["m7i-flex.large"]
  capacity_type   = "ON_DEMAND"

  launch_template {
    id      = aws_launch_template.nodes.id
    version = aws_launch_template.nodes.latest_version
  }

  scaling_config {
    desired_size = 1
    min_size     = 1
    max_size     = 1
  }

  update_config {
    max_unavailable = 1
  }

  depends_on = [aws_iam_role_policy_attachment.eks_node]
}

# A managed node group does not pass its tags down: without this template the node, its disk and its
# network interface carry no Project/Environment. It sets nothing else EKS would otherwise choose,
# apart from the 20 GB disk (disk_size cannot be combined with a template) and IMDSv2.
resource "aws_launch_template" "nodes" {
  name = "${local.name}-eks-nodes"

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 20
      volume_type           = "gp3"
      delete_on_termination = true
    }
  }

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 2 # pods on the node still reach it (vpc-cni, the agent)
  }

  dynamic "tag_specifications" {
    for_each = ["instance", "volume", "network-interface"]
    content {
      resource_type = tag_specifications.value
      tags          = local.tags
    }
  }
}

# EKS creates the cluster security group itself, with only its own tags.
resource "aws_ec2_tag" "cluster_sg" {
  for_each    = local.tags
  resource_id = aws_eks_cluster.this.vpc_config[0].cluster_security_group_id
  key         = each.key
  value       = each.value
}

# Add-ons at the default version for the cluster. Created after the node group: coredns and
# metrics-server need a node to become ACTIVE.
resource "aws_eks_addon" "this" {
  for_each = {
    vpc-cni        = null
    kube-proxy     = null
    coredns        = null
    metrics-server = null
    # EKS Pod Identity: catalog-api's pods get the warden-dev-catalog-pod role (below).
    eks-pod-identity-agent = null
    # Pod-level metrics for the shop alarms; container log shipping off (it is billed per GB and
    # WARDEN reads pod logs through the Kubernetes API anyway).
    amazon-cloudwatch-observability = jsonencode({ containerLogs = { enabled = false } })
  }
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = each.key
  configuration_values        = each.value
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"
  depends_on                  = [aws_eks_node_group.this, aws_cloudwatch_log_group.container_insights]
}

# The observability agent writes here. Created by terraform so a destroy removes it: left to the
# agent it would outlive the stack, untagged.
resource "aws_cloudwatch_log_group" "container_insights" {
  name              = "/aws/containerinsights/${aws_eks_cluster.this.name}/performance"
  retention_in_days = 1
}

# --------------------------------------------------------------------------- catalog-api's identity
#
# catalog-api signs IAM database tokens as user catalog (read-only). EKS Pod Identity hands the
# role to pods of ServiceAccount shop/catalog-api (k8s/fullstack/catalog-api.yaml) - no long-lived
# key. ⚠ Audit 2026-09-28 (A-I-12): the node launch template's IMDS hop limit of 2 still lets any
# pod read the NODE role's credentials, so this is not yet "no node-wide grant"; the fix is hop
# limit 1 plus Pod Identity for the CloudWatch agent.

resource "aws_iam_role" "catalog_pod" {
  name                 = "${local.name}-catalog-pod"
  permissions_boundary = local.permissions_boundary
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = ["sts:AssumeRole", "sts:TagSession"]
      Principal = { Service = "pods.eks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "catalog_pod_db" {
  name = "${local.name}-db-connect"
  role = aws_iam_role.catalog_pod.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ConnectAsCatalog"
      Effect   = "Allow"
      Action   = ["rds-db:connect"]
      Resource = [local.dbuser_arn["catalog"]]
    }]
  })
}

resource "aws_eks_pod_identity_association" "catalog" {
  cluster_name    = aws_eks_cluster.this.name
  namespace       = "shop"
  service_account = "catalog-api"
  role_arn        = aws_iam_role.catalog_pod.arn
}

# EKS — the expensive one, and the one whose value is easiest to overstate.
#
# WARDEN's Kubernetes backend is already proven in CI against a real k3d cluster, and the README
# has said in plain words that it had never been run on managed EKS. This closes exactly that gap
# and nothing more: no new code, no IRSA, no cloud API call from inside the pod. EKS *is*
# Kubernetes, so what is being proven is that the manifests are admitted by a cluster that enforces
# Pod Security for real and that the backend reads it.
#
# ⛔ $0.10/hour for the control plane, running or idle. `-var enable_eks=false` skips this file.

resource "aws_iam_role" "eks_cluster" {
  permissions_boundary = local.permissions_boundary
  count                = var.enable_eks ? 1 : 0
  name                 = "${local.name}-eks-cluster"
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
  count      = var.enable_eks ? 1 : 0
  role       = aws_iam_role.eks_cluster[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_eks_cluster" "this" {
  count    = var.enable_eks ? 1 : 0
  name     = local.name
  role_arn = aws_iam_role.eks_cluster[0].arn

  vpc_config {
    subnet_ids             = aws_subnet.public[*].id
    endpoint_public_access = true
    # ⛔ MUST be true while public_access_cidrs is locked to one address. Nodes reach the API server
    # through whichever endpoint they can: with private access off they go out through the internet
    # gateway, arrive from THEIR OWN public IP, are refused by public_access_cidrs, and the node group
    # fails with "instances failed to join the kubernetes cluster" after ~20 billed minutes. With it
    # on, in-VPC DNS resolves the endpoint to private addresses (enable_dns_hostnames in main.tf) and
    # nodes never touch the public allow-list. Shipped as `false` until 2026-09-24; never caught
    # because the node group never got far enough to try.
    endpoint_private_access = true
    # The API endpoint is reachable from one address by default, not from the internet. This is the
    # setting people leave at 0.0.0.0/0 without noticing - so widening it is an explicit variable.
    public_access_cidrs = coalesce(var.eks_public_access_cidrs, [var.my_ip_cidr])
  }

  access_config {
    authentication_mode = "API_AND_CONFIG_MAP"
    # Without this the account that created the cluster cannot talk to it — the classic first-day
    # EKS surprise, since the old aws-auth ConfigMap path is no longer the default.
    bootstrap_cluster_creator_admin_permissions = true
  }

  depends_on = [aws_iam_role_policy_attachment.eks_cluster]
}

# --------------------------------------------------------------------------- nodes

resource "aws_iam_role" "eks_node" {
  permissions_boundary = local.permissions_boundary
  count                = var.enable_eks ? 1 : 0
  name                 = "${local.name}-eks-node"
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
  for_each = var.enable_eks ? toset([
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
  ]) : toset([])
  role       = aws_iam_role.eks_node[0].name
  policy_arn = each.value
}

# ⛔ ON A FRESH ACCOUNT, CREATE THE NODE-GROUP SERVICE-LINKED ROLE FIRST:
#
#     aws iam create-service-linked-role --aws-service-name eks-nodegroup.amazonaws.com
#
# CreateNodegroup first calls iam:GetRole on AWSServiceRoleForAmazonEKSNodegroup, with the CALLER's
# credentials. While that role does not exist, IAM evaluates the request against the path-less ARN
# `role/AWSServiceRoleForAmazonEKSNodegroup` - which `role/aws-service-role/*` (the boundary's
# CeilingReadServiceLinkedRoles) does not match - and the node group fails. Once the role exists
# its real ARN carries the path and matches. Found 2026-09-24 with IAM's access troubleshooter,
# which showed the path-less resource. Not a Terraform resource on purpose: the operator cannot
# delete service-linked roles, so owning it here would make every destroy fail.
resource "aws_eks_node_group" "this" {
  count           = var.enable_eks ? 1 : 0
  cluster_name    = aws_eks_cluster.this[0].name
  node_group_name = "${local.name}-ng"
  node_role_arn   = aws_iam_role.eks_node[0].arn
  subnet_ids      = aws_subnet.public[*].id

  # One small spot node. The workload under test is a single pod that OOMs on purpose; anything
  # larger is money spent on idle capacity.
  instance_types = ["t3.small"]
  capacity_type  = "SPOT"
  disk_size      = 20

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

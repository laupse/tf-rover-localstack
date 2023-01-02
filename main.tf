provider "aws" {
  region = "eu-west-3"
}

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

data "aws_ec2_managed_prefix_list" "s3" {
  name = "com.amazonaws.${data.aws_region.current.name}.s3"
}

# data "aws_vpc" "selected" {
#   id = aws_vpc.selected.id
# }

resource "aws_vpc" "selected" {

}

resource "aws_subnet" "a" {
  vpc_id = aws_vpc.selected.id
}

resource "aws_subnet" "b" {
  vpc_id = aws_vpc.selected.id
}

data "aws_route_table" "a" {
  subnet_id = aws_subnet.a.id
}

data "aws_route_table" "b" {
  subnet_id = aws_subnet.b.id
}

data "aws_network_acls" "selected" {
  vpc_id = aws_vpc.selected.id
}

locals {
  aws_ec2_managed_prefix_cidr_list = [
    for e in data.aws_ec2_managed_prefix_list.s3.entries : e.cidr
  ]
}

resource "aws_security_group" "vpc_endpoint" {
  name        = "${var.name}-eks-vpc-endpoint"
  description = "Security group for VPC interface endpoint"
  vpc_id      = aws_vpc.selected.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [aws_vpc.selected.cidr_block, "192.168.1.0/24"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_vpc_endpoint" "ec2" {
  vpc_id            = aws_vpc.selected.id
  vpc_endpoint_type = "Interface"
  service_name      = "com.amazonaws.eu-west-3.ec2"
  security_group_ids = [
    aws_security_group.vpc_endpoint.id,
  ]
  subnet_ids          = [aws_subnet.a.id, aws_subnet.b.id]
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "sts" {
  vpc_id            = aws_vpc.selected.id
  vpc_endpoint_type = "Interface"
  service_name      = "com.amazonaws.eu-west-3.sts"
  security_group_ids = [
    aws_security_group.vpc_endpoint.id,
  ]
  subnet_ids          = [aws_subnet.a.id, aws_subnet.b.id]
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "autoscaling" {
  vpc_id            = aws_vpc.selected.id
  vpc_endpoint_type = "Interface"
  service_name      = "com.amazonaws.eu-west-3.autoscaling"
  security_group_ids = [
    aws_security_group.vpc_endpoint.id,
  ]
  subnet_ids          = [aws_subnet.a.id, aws_subnet.b.id]
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "ecr" {
  vpc_id            = aws_vpc.selected.id
  vpc_endpoint_type = "Interface"
  service_name      = "com.amazonaws.eu-west-3.ecr.dkr"
  security_group_ids = [
    aws_security_group.vpc_endpoint.id,
  ]
  subnet_ids          = [aws_subnet.a.id, aws_subnet.b.id]
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "ecr-api" {
  vpc_id            = aws_vpc.selected.id
  vpc_endpoint_type = "Interface"
  service_name      = "com.amazonaws.eu-west-3.ecr.api"
  security_group_ids = [
    aws_security_group.vpc_endpoint.id,
  ]
  subnet_ids          = [aws_subnet.a.id, aws_subnet.b.id]
  private_dns_enabled = true
}

resource "aws_network_acl_rule" "s3" {
  count          = length(local.aws_ec2_managed_prefix_cidr_list)
  network_acl_id = data.aws_network_acls.selected.ids[0]
  rule_number    = 102 + count.index
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = local.aws_ec2_managed_prefix_cidr_list[count.index]
  from_port      = 1024
  to_port        = 65535
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.selected.id
  vpc_endpoint_type = "Gateway"
  service_name      = "com.amazonaws.eu-west-3.s3"
  route_table_ids   = [data.aws_route_table.a.id, data.aws_route_table.b.id]
}

# CONTROL PLANE
resource "aws_iam_role" "cluster" {
  name = "eks-cluster"

  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "eks.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.cluster.name
}


resource "aws_eks_cluster" "eks" {
  name     = var.name
  role_arn = aws_iam_role.cluster.arn

  vpc_config {
    subnet_ids              = [aws_subnet.a.id, aws_subnet.b.id]
    endpoint_private_access = true
    endpoint_public_access  = false
  }

  depends_on = [
    aws_iam_role_policy_attachment.AmazonEKSClusterPolicy,
  ]
}

resource "aws_security_group_rule" "vpn" {
  type              = "ingress"
  from_port         = 0
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["192.168.1.0/24"]
  security_group_id = aws_eks_cluster.eks.vpc_config[0].cluster_security_group_id
}

resource "aws_security_group_rule" "node_port" {
  type              = "ingress"
  from_port         = 30000
  to_port           = 32767
  protocol          = "tcp"
  cidr_blocks       = ["192.168.1.0/24"]
  security_group_id = aws_eks_cluster.eks.vpc_config[0].cluster_security_group_id
}

resource "aws_iam_role" "node-group" {
  name = "${var.name}-eks-node-group"

  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}


# WORKER NODE
resource "aws_iam_role_policy_attachment" "AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.node-group.name
}

resource "aws_iam_role_policy_attachment" "AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.node-group.name
}

resource "aws_iam_role_policy_attachment" "AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.node-group.name
}

resource "aws_eks_node_group" "node-group" {
  cluster_name    = aws_eks_cluster.eks.name
  node_group_name = var.name
  node_role_arn   = aws_iam_role.node-group.arn
  subnet_ids      = [aws_subnet.a.id, aws_subnet.b.id]
  instance_types  = ["t2.medium"]

  remote_access {
    ec2_ssh_key = "LGRONDIN"
  }


  scaling_config {

    desired_size = 2
    max_size     = 2
    min_size     = 0
  }

  depends_on = [
    aws_iam_role_policy_attachment.AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.AmazonEC2ContainerRegistryReadOnly,
    aws_vpc_endpoint.ec2,
    aws_vpc_endpoint.ecr,
    aws_vpc_endpoint.ecr-api,
    aws_vpc_endpoint.s3,
    aws_network_acl_rule.s3,
  ]
}

resource "aws_eks_node_group" "node-group-gpu" {
  cluster_name    = aws_eks_cluster.eks.name
  node_group_name = "${var.name}-gpu"
  node_role_arn   = aws_iam_role.node-group.arn
  subnet_ids      = [aws_subnet.a.id, aws_subnet.b.id]
  instance_types  = ["g4dn.xlarge"]
  ami_type        = "AL2_x86_64_GPU"
  labels = {
    gpu = "true"
  }
  remote_access {
    ec2_ssh_key = "LGRONDIN"
  }

  scaling_config {

    desired_size = 1
    max_size     = 1
    min_size     = 0
  }

  depends_on = [
    aws_iam_role_policy_attachment.AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.AmazonEC2ContainerRegistryReadOnly,
    aws_vpc_endpoint.ec2,
    aws_vpc_endpoint.ecr,
    aws_vpc_endpoint.ecr-api,
    aws_vpc_endpoint.s3,
    aws_network_acl_rule.s3,
  ]
}

data "tls_certificate" "default" {
  url = aws_eks_cluster.eks.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "default" {
  url             = aws_eks_cluster.eks.identity[0].oidc[0].issuer
  client_id_list  = ["sts.amazonaws.com", ]
  thumbprint_list = [data.tls_certificate.default.certificates[0].sha1_fingerprint]

}

### AWS Load Balancer Controller
resource "aws_iam_policy" "load-balancer-controller" {
  name   = "AWSLoadBalancerControllerIAMPolicy"
  policy = file("policies/iam-policy.json")
}

resource "aws_iam_role" "load-balancer-controller" {
  name = "AmazonEKSLoadBalancerControllerRole"

  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRoleWithWebIdentity"
      Effect = "Allow"
      Principal = {
        "Federated" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${trimprefix(aws_eks_cluster.eks.identity[0].oidc[0].issuer, "https://")}"
      }
      Condition = {
        StringEquals = {
          "${trimprefix(aws_eks_cluster.eks.identity[0].oidc[0].issuer, "https://")}:aud" : "sts.amazonaws.com",
          "${trimprefix(aws_eks_cluster.eks.identity[0].oidc[0].issuer, "https://")}:sub" : "system:serviceaccount:kube-system:aws-load-balancer-controller"
        }
      }
    }]
    Version = "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "AWSLoadBalancerControllerIAMPolicy" {
  policy_arn = aws_iam_policy.load-balancer-controller.arn
  role       = aws_iam_role.load-balancer-controller.name
}

### AWS Autoscaler
resource "aws_iam_policy" "cluster-autoscaler" {
  name   = "AmazonEKSClusterAutoscalerPolicy"
  policy = file("policies/cluster-autoscaler-policy.json")
}

resource "aws_iam_role" "cluster-autoscaler" {
  name = "AmazonEKSClusterAutoscalerRole"

  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRoleWithWebIdentity"
      Effect = "Allow"
      Principal = {
        "Federated" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${trimprefix(aws_eks_cluster.eks.identity[0].oidc[0].issuer, "https://")}"
      }
      Condition = {
        StringEquals = {
          "${trimprefix(aws_eks_cluster.eks.identity[0].oidc[0].issuer, "https://")}:sub" : "system:serviceaccount:kube-system:cluster-autoscaler"
        }
      }
    }]
    Version = "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "cluster-autoscaler" {
  policy_arn = aws_iam_policy.cluster-autoscaler.arn
  role       = aws_iam_role.cluster-autoscaler.name
}

data "aws_eks_cluster_auth" "this" {
  name = var.name

  depends_on = [
    aws_eks_cluster.eks
  ]
}




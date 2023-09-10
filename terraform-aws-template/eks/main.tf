module "config" {
  source = "../config"
}


############## CLUSTER DEFINITION ################
resource "aws_iam_role" "eks_cluster_iam" {
  ##eks cluster iam role name need to be change for new one
  name               = "zontal-space-cluster-iam-role-${module.config.envname}"
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": ["eks.amazonaws.com", "ec2.amazonaws.com", "sts.amazonaws.com"]
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY

  tags = {
    Name = "zontal-space-cluster-iam-role-${module.config.envname}"
  }
}

data "aws_caller_identity" "current" {
}
locals {
  oidc_id = substr(aws_eks_cluster.eks_cluster.identity.0.oidc.0.issuer, 8, -1)
}
resource "aws_iam_policy" "eks_manage_policy" {
  ##aws iam policy name needs to be changed
  name        = "ZONTAL-EKS-MANAGER-${module.config.envname}"
  description = "Allows ZONTAL controller machine to manage and modify ZONTAL EKS cluster"

  ##Terraform's "jsonencode" function converts a
  ##Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "VisualEditorUNRESTRICTED",
        "Effect" : "Allow",
        "Action" : [
          "ec2:AuthorizeSecurityGroupIngress",
          "elasticloadbalancing:ModifyListener",
          "ec2:DescribeInstances",
          "iam:ListServerCertificates",
          "ec2:DescribeCoipPools",
          "elasticloadbalancing:SetWebAcl",
          "ec2:DescribeInternetGateways",
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:CreateRule",
          "ec2:DescribeAccountAttributes",
          "elasticloadbalancing:AddListenerCertificates",
          "iam:GetServerCertificate",
          "elasticloadbalancing:DescribeLoadBalancerAttributes",
          "ec2:RevokeSecurityGroupIngress",
          "elasticloadbalancing:DescribeTargetGroupAttributes",
          "acm:DescribeCertificate",
          "elasticloadbalancing:ModifyRule",
          "eks:ListClusters",
          "elasticloadbalancing:DescribeRules",
          "ec2:DescribeSubnets",
          "ec2:DescribeAddresses",
          "elasticloadbalancing:RemoveListenerCertificates",
          "elasticloadbalancing:DescribeListeners",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeAvailabilityZones",
          "ec2:CreateSecurityGroup",
          "acm:ListCertificates",
          "elasticloadbalancing:DescribeListenerCertificates",
          "elasticfilesystem:DescribeFileSystems",
          "cognito-idp:DescribeUserPoolClient",
          "elasticloadbalancing:DescribeSSLPolicies",
          "elasticloadbalancing:DescribeTags",
          "ec2:GetCoipPoolUsage",
          "ec2:DescribeTags",
          "elasticfilesystem:DescribeAccessPoints",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVpcs",
          "elasticloadbalancing:DescribeTargetHealth",
          "elasticloadbalancing:DescribeTargetGroups",
          "eks:DescribeAddonVersions",
          "eks:ListAddons",
          "eks:DescribeAddon",
          "ec2:CreateLaunchTemplate",
          "ec2:DescribeLaunchTemplateVersions",
          "ec2:RunInstances",
          "sts:DecodeAuthorizationMessage",
          "sts:GetServiceBearerToken",
          "ec2:CreateTags",
          "ecr:GetAuthorizationToken"
        ],
        "Resource" : "*"
      },
      {
        "Sid" : "VisualEditor0",
        "Effect" : "Allow",
        "Action" : "ec2:CreateTags",
        "Resource" : "*",
        "Condition" : {
          "StringEquals" : {
            "ec2:CreateAction" : "CreateSecurityGroup"
          },
          "Null" : {
            "aws:RequestTag/elbv2.k8s.aws/cluster" : "false"
          }
        }
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "ec2:CreateSecurityGroup"
        ],
        "Resource" : "*"
      },
      {
        "Sid" : "VisualEditor1",
        "Effect" : "Allow",
        "Action" : [
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus"
        ],
        "Resource" : "*",
        "Condition" : {
          "Null" : {
            "aws:RequestTag/elbv2.k8s.aws/cluster" : "false"
          }
        }
      },
      {
        "Sid" : "VisualEditorEC2INGRESS",
        "Effect" : "Allow",
        "Action" : [
          "ec2:RevokeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:DeleteSecurityGroup"
        ],
        "Resource" : "*",
        "Condition" : {
          "Null" : {
            "aws:ResourceTag/elbv2.k8s.aws/cluster" : "false"
          }
        }
      },
      {
        "Sid" : "VisualEditorEC2TEMPLATEVERSION",
        "Effect" : "Allow",
        "Action" : "ec2:CreateLaunchTemplateVersion",
        "Resource" : "*",
        "Condition" : {
          "StringEquals" : {
            "ec2:ResourceTag/Application" : "Zontal"
          }
        }
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "elasticfilesystem:CreateAccessPoint",
          "elasticfilesystem:DescribeMountTargets"
        ],
        "Resource" : "*"
      },
      {
        "Effect" : "Allow",
        "Action" : "elasticfilesystem:DeleteAccessPoint",
        "Resource" : "*",
        "Condition" : {
          "StringEquals" : {
            "aws:ResourceTag/efs.csi.aws.com/cluster" : "true"
          }
        }
      },
      {
        "Sid" : "VisualEditor6",
        "Effect" : "Allow",
        "Action" : [
          "eks:ListFargateProfiles",
          "eks:DescribeNodegroup",
          "eks:UpdateClusterVersion",
          "eks:ListNodegroups",
          "eks:DeleteNodegroup",
          "eks:ListUpdates",
          "eks:UpdateAddon",
          "eks:DeleteAddon",
          "eks:AccessKubernetesApi",
          "eks:DescribeCluster",
          "eks:CreateNodegroup",
          "ssm:GetParameter"
        ],
        "Resource" : [
          "arn:aws:eks:*:*:cluster/ZONTAL-EKS-CLUSTER-*",
          "arn:aws:eks:*:*:addon/ZONTAL-EKS-CLUSTER-*/*/*",
          "arn:aws:eks:*:*:nodegroup/ZONTAL-EKS-CLUSTER-*/*/*",
          "arn:aws:ssm:*:*:parameter/*"
        ]
      },
      {
        "Sid" : "VisualEditor7",
        "Effect" : "Allow",
        "Action" : [
          "sts:AssumeRole",
          "iam:CreateServiceLinkedRole",
          "iam:ListAttachedRolePolicies"
        ],
        "Resource" : [
          "arn:aws:iam::*:role/zontal-datahub-receiveupdates-*",
          "arn:aws:iam::*:role/zontal-application-nodegroup-*",
          "arn:aws:iam::*:role/zontal-application-manager-*",
          "arn:aws:iam::*:role/zontal-space-cluster-iam-role-*",
          "arn:aws:iam::*:policy/zontal-datahub-receiveupdates-*",
          "arn:aws:iam::*:role/aws-*/*ElasticLoadBalancing",
          "arn:aws:iam::*:role/aws-*/*/*ApplicationAutoScaling_DynamoDBTable"
        ]
      },
      {
        "Sid" : "VisualEditorECR1",
        "Effect" : "Allow",
        "Action" : [
          "ecr:UntagResource",
          "ecr:StartImageScan",
          "ecr:DescribeImages",
          "ecr:TagResource",
          "ecr:BatchDeleteImage",
          "ecr:ListImages",
          "ecr:DeleteRepository",
          "ecr:ReplicateImage",
          "ecr:PutImage",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability",
          "ecr:CompleteLayerUpload",
          "ecr:GetDownloadUrlForLayer",
          "ecr:InitiateLayerUpload",
          "ecr:PutImage",
          "ecr:UploadLayerPart",
          "ecr:CreateRepository"
        ],
        "Resource" : [
          "arn:aws:ecr:*:*:repository/zontal*/*",
          "arn:aws:ecr:*:*:repository/release2401*/*"
        ]
      },
      {
        "Sid" : "VisualEditorELB",
        "Effect" : "Allow",
        "Action" : [
          "elasticloadbalancing:CreateListener",
          "elasticloadbalancing:CreateRule",
          "elasticloadbalancing:SetSecurityGroups",
          "elasticloadbalancing:SetIpAddressType",
          "elasticloadbalancing:SetSubnets",
          "elasticloadbalancing:DeleteRule",
          "elasticloadbalancing:DeleteListener",
          "elasticloadbalancing:CreateLoadBalancer",
          "elasticloadbalancing:ModifyLoadBalancerAttributes"
        ],
        "Resource" : [
          "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/k8s-*/*",
          "arn:aws:elasticloadbalancing:*:*:listener/app/k8s-*/*/*",
          "arn:aws:elasticloadbalancing:*:*:listener/net/k8s-*/*/*",
          "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/k8s-*/*",
          "arn:aws:elasticloadbalancing:*:*:listener-rule/net/k8s-/*/*/*",
          "arn:aws:elasticloadbalancing:*:*:listener-rule/app/k8s-*/*/*/*"
        ]
      },
      {
        "Sid" : "VisualEditorTAGS",
        "Effect" : "Allow",
        "Action" : [
          "elasticloadbalancing:RemoveTags",
          "elasticloadbalancing:AddTags"
        ],
        "Resource" : [
          "arn:aws:elasticloadbalancing:*:*:listener/app/k8s-*/*/*",
          "arn:aws:elasticloadbalancing:*:*:listener/net/k8s-*/*/*",
          "arn:aws:elasticloadbalancing:*:*:listener-rule/net/k8s-/*/*/*",
          "arn:aws:elasticloadbalancing:*:*:listener-rule/app/k8s-*/*/*/*",
          "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/k8s-*/*",
          "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/k8s-*/*"
        ]
      },
      {
        "Sid" : "VisualEditorTARGETGROUPS",
        "Effect" : "Allow",
        "Action" : [
          "elasticloadbalancing:RegisterTargets",
          "elasticloadbalancing:CreateTargetGroup",
          "elasticloadbalancing:DeregisterTargets",
          "elasticloadbalancing:DeleteTargetGroup",
          "elasticloadbalancing:ModifyTargetGroupAttributes",
          "elasticloadbalancing:ModifyTargetGroup",
          "elasticloadbalancing:AddTags"
        ],
        "Resource" : "arn:aws:elasticloadbalancing:*:*:targetgroup/k8s-*/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ZONTAL_EKSManagePolicy" {
  policy_arn = aws_iam_policy.eks_manage_policy.arn
  role       = aws_iam_role.eks_cluster_iam.name
}





resource "aws_eks_cluster" "eks_cluster" {
  name     = "ZONTAL-EKS-CLUSTER-${module.config.envname}"
  role_arn = aws_iam_role.eks_cluster_iam.arn

  enabled_cluster_log_types = ["api", "audit", "controllerManager", "scheduler", "authenticator"]

  version = module.config.eks_cluster_version

  tags = {
    Name                                                                = "ZONTAL-EKS-CLUSTER-${module.config.envname}"
    "kubernetes.io/cluster/ZONTAL-EKS-CLUSTER-${module.config.envname}" = "owned"
  }

  vpc_config {
    endpoint_private_access = true
    endpoint_public_access  = false
    subnet_ids              = [for i in module.config.eks_node_group_subnets : module.config.subnets[i]]
    security_group_ids      = [var.sg.id]
  }

  depends_on = [

    aws_cloudwatch_log_group.zontal_eks,
    aws_iam_role_policy_attachment.Managed_ZONTAL_EKSClusterPolicy,
    aws_iam_role_policy_attachment.ZONTAL_EKSVPCResourceController,
  ]

  lifecycle {
    ignore_changes = [vpc_config[0].subnet_ids]
  }

}

data "external" "eks_ami" {
  program = ["bash", "scripts/get_eks_ami.sh", aws_eks_cluster.eks_cluster.version, module.config.region]
}

data "external" "eks_ami_block_info" {
  program = ["bash", "scripts/get_eks_ami_block.sh", data.external.eks_ami.result.id, module.config.region]
}


data "tls_certificate" "zontal_tls" {
  url = aws_eks_cluster.eks_cluster.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "zontal_iam_roles" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.zontal_tls.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.eks_cluster.identity[0].oidc[0].issuer
}

data "aws_iam_policy_document" "zontal_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.zontal_iam_roles.url, "https://", "")}:sub"
      values   = ["system:serviceaccount:kube-system:aws-node"]
    }

    principals {
      identifiers = [aws_iam_openid_connect_provider.zontal_iam_roles.arn]
      type        = "Federated"
    }
  }
}


#################### LOGGING ############################
resource "aws_cloudwatch_log_group" "zontal_eks" {
  ##The log group name format is /aws/eks/<cluster-name>/cluster
  ##Reference: https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html
  name              = "/aws/eks/ZONTAL-EKS-CLUSTER-${module.config.envname}/cluster"
  retention_in_days = 7

}

#################### ADDONS #############################
resource "aws_eks_addon" "cni" {
  cluster_name      = aws_eks_cluster.eks_cluster.name
  addon_name        = "vpc-cni"
  addon_version     = "v1.12.1-eksbuild.2"
  resolve_conflicts = "OVERWRITE"
}
resource "aws_eks_addon" "kube-proxy" {
  cluster_name      = aws_eks_cluster.eks_cluster.name
  addon_name        = "kube-proxy"
  addon_version     = "v1.24.9-eksbuild.1"
  resolve_conflicts = "OVERWRITE"

}
resource "aws_eks_addon" "coredns" {
  cluster_name      = aws_eks_cluster.eks_cluster.name
  addon_name        = "coredns"
  addon_version     = "v1.8.7-eksbuild.3"
  resolve_conflicts = "OVERWRITE"
}


################## NODE GROUP DEFINITION #################
resource "aws_launch_template" "zontal_eks_application_node_launch" {
  instance_type = module.config.eks_application_instance_type
  block_device_mappings {
    device_name = data.external.eks_ami_block_info.result.name #Overwrite the default root volume path to change default size of volume
    ebs {
      volume_type = module.config.ebs_volume_type_map["eks_application_nodes"]
      volume_size = module.config.ebs_volume_size_map["eks_application_nodes"]
    }
  }
  name_prefix            = "ZONTAL_EKS_NODE_${module.config.envname}_"
  key_name               = module.config.keypair_name
  vpc_security_group_ids = [var.sg.id]

  image_id = data.external.eks_ami.result.id #EKS AWS Linux 2 for K8s v1.19
  ##obtained with the following command
  ##aws ssm get-parameter --name /aws/service/eks/optimized-ami/1.19/amazon-linux-2/recommended/image_id --region <region-code> --query "Parameter.Value" --output text
  tag_specifications {
    resource_type = "instance"

    tags = {
      Name                                                        = "${module.config.envname}-eksnode"
      "kubernetes.io/cluster/${aws_eks_cluster.eks_cluster.name}" = "owned"
      Application                                                 = "Zontal" #added to help restrict network interface permissions for EKS nodes
    }
  }

  user_data = base64encode(templatefile("eks/userdata-application.tpl", {
    CLUSTER_NAME                      = aws_eks_cluster.eks_cluster.name,
    CLUSTER_ARN                       = aws_iam_role.eks_cluster_iam.arn,
    B64_CLUSTER_CA                    = aws_eks_cluster.eks_cluster.certificate_authority[0].data,
    API_SERVER_URL                    = aws_eks_cluster.eks_cluster.endpoint,
    EFS_ID                            = var.efs_id,
    EFS_MONGO_ID                      = var.efs_mongo_id,
    REGION                            = module.config.region,
    EFS_MOUNT_POINT                   = module.config.efs_mount_point,
    EFS_MONGO_MOUNT_POINT             = module.config.efs_mongo_mount_point,
    DEPLOYMENT_USER                   = module.config.deployment_user,
    SQS_TRANSITIONS_RETRY_URL         = var.sqs_transitions_retry_url,
    SQS_TRANSITIONS_RETRY_ARN         = var.sqs_transitions_retry_arn,
    SNS_TRANSITIONS_FAILURE_TOPIC_ARN = var.sns_transitions_failure_topic_arn
  }))

}



resource "aws_launch_template" "zontal_eks_mongodb_node_launch" {
  instance_type = module.config.eks_mongodb_node_instance_type
  count         = module.config.enable_datahub ? 1 : 0
  block_device_mappings {
    device_name = data.external.eks_ami_block_info.result.name #Overwrite the default root volume path to change default size of volume
    ebs {
      volume_type = module.config.ebs_volume_type_map["eks_mongodb_nodes"]
      volume_size = module.config.ebs_volume_size_map["eks_mongodb_nodes"]
    }
  }
  name_prefix            = "ZONTAL_EKS_MONGODB_NODE_${module.config.envname}_"
  key_name               = module.config.keypair_name
  vpc_security_group_ids = [var.sg.id]

  image_id = data.external.eks_ami.result.id #EKS AWS Linux 2 for K8s
  tag_specifications {
    resource_type = "instance"

    tags = {
      Name                                                        = "${module.config.envname}-mongodb-eksnode"
      "kubernetes.io/cluster/${aws_eks_cluster.eks_cluster.name}" = "owned"
      Application                                                 = "Zontal" #added to help restrict network interface permissions for EKS nodes
    }
  }

  user_data = base64encode(templatefile("eks/userdata-mongodb.tpl", {
    CLUSTER_NAME   = aws_eks_cluster.eks_cluster.name,
    B64_CLUSTER_CA = aws_eks_cluster.eks_cluster.certificate_authority[0].data,
    API_SERVER_URL = aws_eks_cluster.eks_cluster.endpoint
  }))

}


resource "aws_iam_role" "zontal_application_nodegroup" {
  name = "zontal-application-nodegroup-${module.config.envname}"
  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = ["ec2.amazonaws.com", "sts.amazonaws.com"]
      }
      },
      {
        "Sid" : "ALBController",
        "Effect" : "Allow",
        "Principal" : {
          "Federated" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${local.oidc_id}"
        },
        "Action" : "sts:AssumeRoleWithWebIdentity",
        "Condition" : {
          "StringEquals" : {
            "${local.oidc_id}:sub" : "system:serviceaccount:kube-system:aws-load-balancer-controller"
          }
        }
      },
      {
        "Sid" : "PVCAllow"
        "Effect" : "Allow",
        "Principal" : {
          "Federated" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${local.oidc_id}"
        },
        "Action" : "sts:AssumeRoleWithWebIdentity",
        "Condition" : {
          "StringEquals" : {
            "${local.oidc_id}:sub" : "system:serviceaccount:kube-system:efs-csi-controller-sa"
          }
        }
    }]
    Version = "2012-10-17"
  })
}


resource "aws_iam_role" "zontal_application_manager" {
  name = "zontal-application-manager-${module.config.envname}"
  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = ["ec2.amazonaws.com", "sts.amazonaws.com"]
      }
    }]
    Version = "2012-10-17"
  })
}

resource "aws_iam_policy" "restricted_s3_access_policy" {
  name        = "restricted_s3_access_policy_${module.config.envname}"
  description = "Policy to allow worker node of eks cluster to access s3 bucket."

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "VisualEditor0",
        "Effect" : "Allow",
        "Action" : [
          "s3:PutEncryptionConfiguration",
          "s3:GetEncryptionConfiguration",
          "s3:PutBucketAcl",
          "s3:PutBucketPolicy",
          "s3:CreateBucket",
          "s3:ListBucket",
          "s3:GetBucketAcl",
          "s3:DeleteBucket",
          "s3:DeleteBucketPolicy",
          "s3:GetBucketPolicy",
          "s3:GetBucketLocation"
        ],
        "Resource" : [
          "arn:aws:s3:::*-zontal-ingest",
          "arn:aws:s3:::*datahub*",
          "arn:aws:s3:::space-receiveupdates*",
          "arn:aws:s3:::*-adms-api-*-serverlessdeployment*",
          "arn:aws:s3:::python-certificates-laye-serverlessdeploymentbuck*"
        ]
      },
      {
        "Sid" : "VisualEditor1",
        "Effect" : "Allow",
        "Action" : [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject",
          "s3:PutObjectAcl",
          "s3:ListMultipartUploadParts"
        ],
        "Resource" : [
          "arn:aws:s3:::*-zontal-ingest/*",
          "arn:aws:s3:::*datahub*/*",
          "arn:aws:s3:::*-adms-api-*-serverlessdeployment*/*",
          "arn:aws:s3:::space-receiveupdates*",
          "arn:aws:s3:::python-certificates-laye-serverlessdeploymentbuck*/*"
        ]
      }
    ]
  })
}


resource "aws_iam_policy" "component_policy" {
  name        = "component_policy_${module.config.envname}"
  description = "Policy to allow worker node of eks cluster to access efs."

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : [
          "elasticfilesystem:DescribeAccessPoints",
          "elasticfilesystem:TagResource",
          "elasticfilesystem:DescribeFileSystems"
        ],
        "Resource" : "*"
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "elasticfilesystem:CreateAccessPoint"
        ],
        "Resource" : "*",
        "Condition" : {
          "StringLike" : {
            "aws:RequestTag/efs.csi.aws.com/cluster" : "true"
          }
        }
      },
      {
        "Effect" : "Allow",
        "Action" : "elasticfilesystem:DeleteAccessPoint",
        "Resource" : "*",
        "Condition" : {
          "StringEquals" : {
            "aws:ResourceTag/efs.csi.aws.com/cluster" : "true"
          }
        }
      },
      {
        "Sid" : "VisualEditor0",
        "Effect" : "Allow",
        "Action" : [
          "sqs:DeleteMessage",
          "sqs:ChangeMessageVisibility",
          "sqs:SendMessage"
        ],
        "Resource" : [
          "${var.sqs_transitions_retry_arn}", "${var.sqs_notification_fifo_queue_arn}"
        ]
      },
      {
        "Action" : [
          "iam:CreatePolicy",
          "iam:UpdateRole",
          "elasticloadbalancing:SetRulePriorities",
          "iam:ListPolicies",
          "s3:ListBucket",
          "iam:DeletePolicy"
        ],
        "Effect" : "Allow",
        "Resource" : [
          "arn:aws:iam::*:policy/zontal-*-deployment-policy",
          "arn:aws:iam::*:role/zontal-application-manager-*",
          "arn:aws:elasticloadbalancing:*:*:listener-rule/app/k8s-*",
          "arn:aws:iam::*:policy/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "zontal-application-nodegroup-AmazonEFSWorkerNodePolicy" {
  policy_arn = aws_iam_policy.component_policy.arn
  role       = aws_iam_role.zontal_application_nodegroup.name
}

resource "aws_iam_role_policy_attachment" "zontal-application-manager-AmazonEFSWorkerNodePolicy" {
  policy_arn = aws_iam_policy.component_policy.arn
  role       = aws_iam_role.zontal_application_manager.name
}

resource "aws_iam_policy" "eks_node_serverless_policy" {
  name        = "serverless_policy_${module.config.envname}"
  description = "Policy to allow worker node of eks cluster to serverless."

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "VisualEditor0",
        "Effect" : "Allow",
        "Action" : [
          "SNS:ListSubscriptions",
          "iam:GetRole",
          "application-autoscaling:RegisterScalableTarget",
          "lambda:ListFunctions",
          "application-autoscaling:DeleteScheduledAction",
          "apigateway:*",
          "lambda:PublishLayerVersion",
          "lambda:CreateEventSourceMapping",
          "application-autoscaling:DeleteScalingPolicy",
          "SNS:Unsubscribe",
          "lambda:ListEventSourceMappings",
          "application-autoscaling:PutScalingPolicy",
          "lambda:ListLayerVersions",
          "lambda:ListLayers",
          "lambda:GetEventSourceMapping",
          "lambda:DeleteEventSourceMapping",
          "SNS:ListTopics",
          "application-autoscaling:PutScheduledAction",
          "events:*",
          "SQS:ListQueues",
          "application-autoscaling:DeregisterScalableTarget",
          "secretsmanager:ListSecrets",
          "cloudformation:ValidateTemplate",
          "dynamodb:DescribeTable",
          "dynamodb:CreateTable",
          "dynamodb:UpdateTable",
          "application-autoscaling:Describe*"
        ],
        "Resource" : "*"
      },
      {
        "Sid" : "VisualEditorSM",
        "Effect" : "Allow",
        "Action" : [
          "secretsmanager:DescribeSecret",
          "secretsmanager:PutSecretValue",
          "secretsmanager:DeleteSecret",
          "secretsmanager:TagResource",
          "secretsmanager:UntagResource",
          "secretsmanager:CreateSecret",
          "secretsmanager:GetSecretValue",
          "secretsmanager:RotateSecret",
          "secretsmanager:UpdateSecret"
        ],
        "Resource" : [
          "arn:aws:secretsmanager:*:*:secret:platform-*-secret-*",
          "arn:aws:secretsmanager:*:*:secret:*-adms-api-*-secret*"
        ]
      },
      {
        "Sid" : "VisualEditorIAM",
        "Effect" : "Allow",
        "Action" : [
          "iam:CreateRole",
          "iam:AttachRolePolicy",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:DetachRolePolicy",
          "iam:ListAttachedRolePolicies",
          "iam:DeleteRole",
          "iam:PassRole"
        ],
        "Resource" : [
          "arn:aws:iam::*:role/*datahub-receiveupdates-*",
          "arn:aws:iam::*:role/space-receiveupdates-*",
          "arn:aws:iam::*:role/zontal-application-nodegroup-*",
          "arn:aws:iam::*:role/zontal-application-manager-*",
          "arn:aws:iam::*:role/zontal-space-cluster-iam-role-*",
          "arn:aws:iam::*:role/*-adms-api-*",
          "arn:aws:iam::*:role/aws-service-role/dynamodb.application-autoscaling.amazonaws.com/AWSServiceRoleForApplicationAutoScaling_DynamoDBTable",
          "arn:aws:iam::*:policy/*datahub-receiveupdates-*"
        ]
      },
      {
        "Sid" : "VisualEditorSQS",
        "Effect" : "Allow",
        "Action" : [
          "SQS:DeleteQueue",
          "SQS:SetQueueAttributes",
          "SQS:AddPermission",
          "SQS:PurgeQueue",
          "SQS:DeleteMessage",
          "SQS:GetQueueUrl",
          "SQS:SendMessage",
          "SQS:CreateQueue",
          "SQS:GetQueueAttributes",
          "SQS:ReceiveMessage",
          "SQS:RemovePermission"
        ],
        "Resource" : [
          "arn:aws:sqs:*:*:*datahub-receiveupdates-*-spaceNotification-sqsQueue.fifo",
          "arn:aws:sqs:*:*:*datahub-receiveupdates-*-spaceNotification-sqsQueue-retry.fifo",
          "arn:aws:sqs:*:*:*-common-notifications-*-spaceNotification-ais-sqsQueue.fifo"
        ]
      },
      {
        "Sid" : "VisualEditorSNS",
        "Effect" : "Allow",
        "Action" : [
          "SNS:ConfirmSubscription",
          "SNS:Subscribe",
          "SNS:RemovePermission",
          "SNS:AddPermission"
        ],
        "Resource" : [
          "arn:aws:sns:*:*:*-space-notification",
          "arn:aws:sns:*:*:space-common-notifications-*-spaceNotification-snsTopic.fifo"
        ]
      },
      {
        "Sid" : "VisualEditorLambda",
        "Effect" : "Allow",
        "Action" : [
          "lambda:CreateFunction",
          "lambda:DeleteFunction",
          "lambda:InvokeFunction",
          "lambda:AddLayerVersionPermission",
          "lambda:UpdateFunctionCode",
          "lambda:PublishVersion",
          "lambda:ListVersionsByFunction",
          "lambda:GetLayerVersion",
          "lambda:GetLayerVersionPolicy",
          "lambda:RemoveLayerVersionPermission",
          "lambda:ListTags",
          "lambda:DeleteLayerVersion",
          "lambda:UpdateEventSourceMapping",
          "lambda:GetFunction",
          "lambda:UpdateFunctionConfiguration",
          "lambda:AddPermission",
          "lambda:RemovePermission",
          "lambda:ListTags",
          "lambda:TagResource"
        ],
        "Resource" : [
          "arn:aws:lambda:*:*:event-source-mapping:*",
          "arn:aws:lambda:*:*:function:*-adms-api-*",
          "arn:aws:lambda:*:*:function:*datahub-receiveupdates-*",
          "arn:aws:lambda:*:*:function:space-receiveupdates-*",
          "arn:aws:lambda:*:*:layer:*:*"
        ]
      },
      {
        "Sid" : "VisualEditorCloudwatch",
        "Effect" : "Allow",
        "Action" : "logs:*",
        "Resource" : [
          "arn:aws:logs:*:*:destination:*",
          "arn:aws:logs:*:*:log-group:/aws/lambda/*-adms-api-*",
          "arn:aws:logs:*:*:log-group:aws/lambda/*datahub-receiveupdates-*",
          "arn:aws:logs:*:*:log-group:/aws/lambda/*datahub-receiveupdates-*:log-stream:*",
          "arn:aws:logs:*:*:log-group:aws/lambda/*space-receiveupdates-*",
          "arn:aws:logs:*:*:log-group:/aws/lambda/*space-receiveupdates-*:log-stream:*"
        ]
      },
      {
        "Sid" : "VisualEditorLogRetentionPolicy",
        "Effect" : "Allow",
        "Action" : "logs:PutRetentionPolicy",
        "Resource" : "arn:aws:logs:*:*:log-group:/aws/lambda/space-receiveupdates-*"
      },
      {
        "Sid" : "VisualEditorCloudformation",
        "Effect" : "Allow",
        "Action" : "cloudformation:*",
        "Resource" : [
          "arn:aws:cloudformation:*:*:stackset/*:*",
          "arn:aws:cloudformation:*:*:stack/*datahub-receiveupdates-*/*",
          "arn:aws:cloudformation:*:*:stack/space-receiveupdates-*/*",
          "arn:aws:cloudformation:*:*:stack/*-adms-api-*/*",
          "arn:aws:cloudformation:*:*:changeSet/*datahub-receiveupdates-*-change-set/*",
          "arn:aws:cloudformation:*:*:changeSet/space-receiveupdates-*-change-set/*",
          "arn:aws:cloudformation:*:*:changeSet/*-adms-api-*-change-set/*",
          "arn:aws:cloudformation:*:*:stack/python-certificates-*/*"
        ]
      },
      {
        "Sid" : "VisualEditorDynamoDB",
        "Effect" : "Allow",
        "Action" : "dynamodb:*",
        "Resource" : [
          "arn:aws:dynamodb:*:*:table/*-adms-api-*",
          "arn:aws:dynamodb::*:global-table/*-adms-api-*",
          "arn:aws:dynamodb:*:*:table/zontal-datahub-receiveupdates-*-dagruns-table"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "zontal-application-nodegroup-AmazonServerlessWorkerNodePolicy" {
  policy_arn = aws_iam_policy.eks_node_serverless_policy.arn
  role       = aws_iam_role.zontal_application_nodegroup.name
}

resource "aws_iam_role_policy_attachment" "zontal-application-manager-AmazonServerlessWorkerNodePolicy" {
  policy_arn = aws_iam_policy.eks_node_serverless_policy.arn
  role       = aws_iam_role.zontal_application_manager.name
}

resource "aws_iam_policy" "eks_node_service_policy" {
  name        = "service_policy_${module.config.envname}"
  description = "grants minimal permissions to AWS services"

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "VisualEditor0",
        "Effect" : "Allow",
        "Action" : [
          "sns:Publish",
          "sns:Subscribe"
        ],
        "Resource" : [var.sns_notification_fifo_topic_arn, var.sns_notification_topic_arn, var.sns_transitions_failure_topic_arn]
      },
      {
        "Sid" : "VisualEditor2",
        "Effect" : "Allow",
        "Action" : [
          "sqs:DeleteMessage",
          "sqs:ChangeMessageVisibility",
          "sqs:SendMessage"
        ],
        "Resource" : [
          "${var.sqs_transitions_retry_arn}"
        ]
      },
      {
        "Sid" : "VisualEditor3",
        "Effect" : "Allow",
        "Action" : [
          "codeartifact:GetAuthorizationToken",
          "codeartifact:GetRepositoryEndpoint",
          "codeartifact:GetPackageVersionAsset",
          "codeartifact:ReadFromRepository",
          "codeartifact:ListDomains",
          "codeartifact:ListPackageVersionDependencies",
          "codeartifact:ListRepositoriesInDomain",
          "codeartifact:ListPackages",
          "codeartifact:ListPackageVersions",
          "codeartifact:ListTagsForResource",
          "codeartifact:ListPackageVersionAssets",
          "codeartifact:ListRepositories",
          "codeartifact:DescribeDomain",
          "codeartifact:DescribePackage",
          "codeartifact:DescribePackageVersion",
          "codeartifact:DescribeRepository"
        ],
        "Resource" : [
          "arn:aws:codeartifact:${module.config.region}:${data.aws_caller_identity.current.account_id}:repository/zontal-development/pypi",
          "arn:aws:codeartifact:${module.config.region}:${data.aws_caller_identity.current.account_id}:domain/zontal-development"
        ]
      },
      {
        "Effect" : "Allow",
        "Action" : "sts:GetServiceBearerToken",
        "Resource" : "arn:aws:iam::*:role/zontal-application-nodegroup-*",
        "Condition" : {
          "StringEquals" : {
            "sts:AWSServiceName" : "codeartifact.amazonaws.com"
          }
        }
      }
    ]
  })
}
resource "aws_iam_policy" "restricted_CloudWatchAgentServerPolicy" {
  name        = "restricted_CloudWatchAgentServerPolicy_${module.config.envname}"
  description = "Permissions required to use AmazonCloudWatchAgent on servers"

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "VisualEditorEC2",
        "Effect" : "Allow",
        "Action" : [
          "cloudwatch:PutMetricData",
          "ec2:DescribeTags",
          "ec2:DescribeVolumes"
        ],
        "Resource" : "*"
      },
      {
        "Sid" : "VisualEditorLOGSTREAM",
        "Effect" : "Allow",
        "Action" : [
          "logs:DeleteLogStream",
          "logs:PutLogEvents",
          "ssm:GetParameter"
        ],
        "Resource" : [
          "arn:aws:logs:*:*:log-group:/aws/lambda/zontal-datahub-receiveupdates-*:log-stream:*",
          "arn:aws:logs:*:*:log-group:/aws/lambda/space-receiveupdates-*:log-stream:*",
          "arn:aws:logs:*:*:log-group:/aws/lambda/*-adms-api-*:log-stream:*",
          "arn:aws:logs:*:*:log-group:/aws/eks/ZONTAL-EKS-CLUSTER-*/cluster:log-stream:*",
          "arn:aws:ssm:*:*:parameter/AmazonCloudWatch-*"
        ]
      },
      {
        "Sid" : "VisualEditorLOGS",
        "Effect" : "Allow",
        "Action" : [
          "logs:CreateLogStream",
          "logs:DescribeLogGroups",
          "logs:DeleteLogGroup",
          "logs:DescribeLogStreams",
          "logs:CreateLogGroup"
        ],
        "Resource" : [
          "arn:aws:logs:*:*:log-group:/aws/lambda/*-adms-api-*:*",
          "arn:aws:logs:*:*:log-group:/aws/eks/ZONTAL-EKS-CLUSTER-*/cluster:*",
          "arn:aws:logs:*:*:log-group:/aws/lambda/*datahub-receiveupdates-*:*",
          "arn:aws:logs:*:*:log-group:/aws/lambda/space-receiveupdates-*:*"
        ]
      }
    ]
  })
}

resource "aws_iam_policy" "restricted_AmazonEKSVPCResourceController" {
  name        = "restricted_AmazonEKSVPCResourceController_${module.config.envname}"
  description = "Policy used by VPC Resource Controller to manage ENI and IPs for worker nodes."

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "VisualEditorENI0",
        "Effect" : "Allow",
        "Action" : "ec2:CreateNetworkInterfacePermission",
        "Resource" : "*",
        "Condition" : {
          "ForAnyValue:StringEquals" : {
            "ec2:ResourceTag/Application" : "Zontal"
          }
        }
      },
      {
        "Sid" : "VisualEditorENI1",
        "Effect" : "Allow",
        "Action" : [
          "ec2:CreateNetworkInterface",
          "ec2:DetachNetworkInterface",
          "ec2:ModifyNetworkInterfaceAttribute",
          "ec2:DeleteNetworkInterface",
          "ec2:AttachNetworkInterface",
          "ec2:UnassignPrivateIpAddresses",
          "ec2:AssignPrivateIpAddresses"
        ],
        "Resource" : "*",
        "Condition" : {
          "ForAnyValue:StringEquals" : {
            "ec2:ResourceTag/Application" : "Zontal"
          }
        }
      },
      {
        "Sid" : "VisualEditorENI2",
        "Effect" : "Allow",
        "Action" : "ec2:DescribeNetworkInterfaces",
        "Resource" : "*"
      }
    ]
  })
}




resource "aws_iam_role_policy_attachment" "zontal-application-nodegroup-AmazonSnsWorkerNodePolicy" {
  policy_arn = aws_iam_policy.eks_node_service_policy.arn
  role       = aws_iam_role.zontal_application_nodegroup.name
}


resource "aws_iam_role_policy_attachment" "zontal-application-manager-AmazonSnsWorkerNodePolicy" {
  policy_arn = aws_iam_policy.eks_node_service_policy.arn
  role       = aws_iam_role.zontal_application_manager.name
}

resource "aws_iam_role_policy_attachment" "zontal-application-nodegroup-AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.zontal_application_nodegroup.name
}

resource "aws_iam_role_policy_attachment" "Managed_ZONTAL_EKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster_iam.name
}

resource "aws_iam_role_policy_attachment" "zontal-application-nodegroup-CloudWatchAgent" {
  policy_arn = aws_iam_policy.restricted_CloudWatchAgentServerPolicy.arn
  role       = aws_iam_role.zontal_application_nodegroup.name
}

resource "aws_iam_role_policy_attachment" "zontal-application-manager-CloudWatchAgent" {
  policy_arn = aws_iam_policy.restricted_CloudWatchAgentServerPolicy.arn
  role       = aws_iam_role.zontal_application_manager.name
}
resource "aws_iam_role_policy_attachment" "ZONTAL_EKSVPCResourceController" {
  policy_arn = aws_iam_policy.restricted_AmazonEKSVPCResourceController.arn
  role       = aws_iam_role.eks_cluster_iam.name
}


resource "aws_iam_role_policy_attachment" "zontal-application-nodegroup-AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.zontal_application_nodegroup.name
}

resource "aws_iam_role_policy_attachment" "zontal-application-nodegroup-AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.zontal_application_nodegroup.name
}

resource "aws_iam_role_policy_attachment" "zontal-application-manager-AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.zontal_application_manager.name
}

resource "aws_iam_role_policy_attachment" "zontal-application-nodegroup-AmazonS3FullAccess" {
  policy_arn = aws_iam_policy.restricted_s3_access_policy.arn
  role       = aws_iam_role.zontal_application_nodegroup.name
}

resource "aws_iam_role_policy_attachment" "zontal-application-manager-AmazonS3FullAccess" {
  policy_arn = aws_iam_policy.restricted_s3_access_policy.arn
  role       = aws_iam_role.zontal_application_manager.name
}


resource "aws_iam_role_policy_attachment" "zontal-application-manager-AmazonSSMManagedInstanceCore" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  role       = aws_iam_role.zontal_application_manager.name
}



resource "aws_eks_node_group" "application" {
  cluster_name    = aws_eks_cluster.eks_cluster.name
  node_group_name = "APPLICATION-${module.config.envname}"
  node_role_arn   = aws_iam_role.zontal_application_nodegroup.arn
  subnet_ids      = [for i in module.config.eks_node_group_subnets : module.config.subnets[i]]

  tags = {
    Name = "${module.config.envname}-NODEGROUP"
  }

  launch_template {
    id      = aws_launch_template.zontal_eks_application_node_launch.id
    version = aws_launch_template.zontal_eks_application_node_launch.default_version
  }

  scaling_config {
    desired_size = module.config.eks_application_node_instance_count
    max_size     = module.config.eks_application_node_instance_count
    min_size     = 1
  }

  depends_on = [
    aws_iam_role_policy_attachment.zontal-application-nodegroup-AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.zontal-application-nodegroup-AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.zontal-application-nodegroup-AmazonEC2ContainerRegistryReadOnly,
  ]
}



resource "aws_eks_node_group" "mongodb" {
  cluster_name    = aws_eks_cluster.eks_cluster.name
  node_group_name = "MONGODB-${module.config.envname}"
  node_role_arn   = aws_iam_role.zontal_application_nodegroup.arn
  subnet_ids      = [for i in module.config.eks_node_group_subnets : module.config.subnets[i]]

  tags = {
    Name = "${module.config.envname}-MONGODB-NODEGROUP"
  }

  labels = {
    "nodegroup_purpose" = "mongodb"
  }
  taint {
    key    = "dedicated"
    value  = "mongodb"
    effect = "NO_SCHEDULE"
  }

  launch_template {
    id      = try(element(aws_launch_template.zontal_eks_mongodb_node_launch.*.id, 0), "")
    version = try(element(aws_launch_template.zontal_eks_mongodb_node_launch.*.default_version, 0), "")
  }
  count = module.config.enable_datahub ? 1 : 0
  scaling_config {
    desired_size = module.config.eks_mongodb_node_instance_count
    max_size     = module.config.eks_mongodb_node_instance_count
    min_size     = 1
  }
  depends_on = [
    aws_iam_role_policy_attachment.zontal-application-nodegroup-AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.zontal-application-nodegroup-AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.zontal-application-nodegroup-AmazonEC2ContainerRegistryReadOnly,
  ]
}


resource "aws_iam_role_policy_attachment" "ZONTAL_EKSWorkerManagePolicy" {
  policy_arn = aws_iam_policy.eks_manage_policy.arn
  role       = aws_iam_role.zontal_application_nodegroup.name
}

resource "aws_iam_role_policy_attachment" "ZONTAL_EKSWorkerManagePolicyForManagerNode" {
  policy_arn = aws_iam_policy.eks_manage_policy.arn
  role       = aws_iam_role.zontal_application_manager.name
}

###################### PERMISSION FIXES ###############################
resource "local_file" "kube_auth" {
  content  = templatefile("scripts/update_kube_authmap.yml.tpl", { EC2_ROLE_ARN = aws_iam_role.eks_cluster_iam.arn, APPLICATION_IAM = aws_iam_role.zontal_application_nodegroup.arn, EKS_CONSOLE_ROLE_ARN = module.config.eks_console_role_arn, MANAGER_ROLE_ARN = aws_iam_role.zontal_application_manager.arn })
  filename = "scripts/update_kube_authmap.yml"
}

resource "null_resource" "update_kube_auth" {
  provisioner "local-exec" {
    command = "aws eks update-kubeconfig --region ${module.config.region} --name ${aws_eks_cluster.eks_cluster.name}"
  }
  depends_on = [aws_eks_node_group.application]
}
resource "null_resource" "add_kube_auth" {
  provisioner "local-exec" {
    command = "kubectl apply -f scripts/update_kube_authmap.yml"
  }
  depends_on = [null_resource.update_kube_auth, local_file.kube_auth]
}

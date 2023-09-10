module "config" {
  source = "./config"
}

terraform {
  backend "s3" {
    bucket         = "zontal-<aws-account-env>-terraform-state-files"   # i.e. zontal-devrelated-terraform-state-files
    key            = "<env-name>/terraform.tfstate"                     # i.e. thor/terraform.tfstate
    region         = "<aws-region>"
    dynamodb_table = "<dynamo-db-table>"
  }
}

// rolypoly s3
/*terraform {
  backend "s3" {
    bucket = "tc-remotestate-36217"
    key = "terraform-aws/terraform.tfstate"
    region = "eu-central-1"
    dynamodb_table = "terraformf-remote-state-lock-rolypoly"
  }
}*/

provider "aws" {
  region = module.config.region
  // access key id is stored in environment variable AWS_ACCESS_KEY_ID
  // secret is stored in AWS_SECRET_ACCESS_KEY
  // often defined in .bashrc or from CI/CD tool
  default_tags {
    tags = module.config.tags_default
  }
}

module "vpc" {
  source = "./vpc"
}

module "rt53" {
  source = "./rt53"
}

/*
module "keys" {
    source = "./keys"
}
*/

module "efs" {
  source  = "./efs"
  subnets = module.config.subnets
  sg      = module.vpc.zontal_app_sg
}

module "eks" {
    source = "./eks"
    efs_id = module.efs.efs_id
    efs_mongo_id = module.efs.efs_mongo_id
    sg = module.vpc.zontal_app_sg
    subnets = module.config.subnets
    sns_notification_fifo_topic_arn = module.sns.aws_platform_sns_notification_fifo_topic_arn
    sqs_transitions_retry_url = module.sqs.aws_platform_sqs_transitions_retry_url
    sqs_transitions_retry_arn = module.sqs.aws_platform_sqs_transitions_retry_arn
    sns_transitions_failure_topic_arn = module.sns.aws_platform_sns_transitions_failure_topic_arn
    sns_notification_topic_arn = module.sns.aws_platform_sns_notification_topic_arn
	  sqs_notification_fifo_queue_arn = module.sqs.aws_platform_sqs_notification_fifo_queue_arn
    sm_arn = module.sm.sm_arn
}

module "ec2" {
    source = "./ec2"
    add_kube_auth_id = module.eks.add_kube_auth_id
    sg = module.vpc.zontal_app_sg
    sg_public = module.vpc.zontal_app_public_sg
    subnets = module.config.subnets
    eks_worker_iam = module.eks.eks_worker_iam
    manager_iam = module.eks.manager_iam
    eks_cluster_iam = module.eks.eks_cluster_iam
    eks_cluster = module.eks.eks_cluster
    efs_id = module.efs.efs_id
    efs_mongo_id = module.efs.efs_mongo_id
    zone_id = module.rt53.zone_id
    sm_id = module.sm.sm_id
    lambda_sg_id = module.vpc.lambda_sg.id
    sns_notification_topic_arn = module.sns.aws_platform_sns_notification_topic_arn
    sns_notification_fifo_topic_arn = module.sns.aws_platform_sns_notification_fifo_topic_arn
	  sqs_notification_fifo_queue_url = module.sqs.aws_platform_sqs_notification_fifo_queue_url
    sqs_transitions_retry_url = module.sqs.aws_platform_sqs_transitions_retry_url
    sqs_transitions_retry_arn = module.sqs.aws_platform_sqs_transitions_retry_arn
    sns_transitions_failure_topic_arn = module.sns.aws_platform_sns_transitions_failure_topic_arn
    rds = module.rds.rds
    eks_cluster_security_group_id = module.eks.eks_cluster_security_group_id
}

module "s3" {
  source = "./s3"
}

module "sns" {
  source = "./sns"
}

module "sqs" {
  source = "./sqs"
  sns_notification_fifo_topic_arn = module.sns.aws_platform_sns_notification_fifo_topic_arn
  sqs_notification_fifo_queue_arn = module.sqs.aws_platform_sqs_notification_fifo_queue_arn
  sqs_notification_fifo_queue_id  = module.sqs.aws_platform_sqs_notification_fifo_queue_id
}

module "sm" {
  source = "./sm"
}
module "kms" {
  source = "./kms"
  
}
module "rds" {
  source  = "./rds"
  sg      = module.vpc.zontal_app_sg
  subnets = module.config.subnets
  zontal_kms_arn    = module.kms.zontal_kms_arn
  
}

module "codeartifact" {
  source                      = "./codeartifact"
  domain_name                 = module.config.domain_name
  repository_pypi_name        = module.config.repository_pypi_name
  repository_pypi_description = module.config.repository_pypi_description
  manager_iam                 = module.eks.manager_iam
}

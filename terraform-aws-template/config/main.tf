output "region" {
    value = var.region
}
output "tags_default" {
    value = var.tags_default
}
output "envname"{
    value = var.envname
}
output "envdomain"{
    value = var.envdomain
}

output "vpc_id" {
    value = var.vpc_id
}

output "subnets" {
    value =var.subnets
}

output "vpc_cidr_block" {
    value = var.vpc_cidr_block
}

output "ec2_manager_instance_type" {
    value = var.ec2_manager_instance_type
}
output "eks_application_node_instance_count" {
    value = var.eks_application_node_instance_count
}

output "eks_application_instance_type" {
    value = var.eks_application_instance_type
}


output "eks_mongodb_node_instance_count" {
    value = var.eks_mongodb_node_instance_count
}

output "eks_mongodb_node_instance_type" {
    value = var.eks_mongodb_node_instance_type
}

output "rds_instance_type" {
    value = var.rds_instance_type
}
output "rds_password" {
    value = var.rds_password
}
output "keypair_name" {
    value = var.keypair_name
}

output "terraform_machine_cidr_range" {
    value = var.terraform_machine_cidr_range
}

output "ec2_elasticsearch_instance_type" {
    value = var.ec2_elasticsearch_instance_type
}

output "eks_node_group_subnets" {
    value = var.eks_node_group_subnets
}

output "serverless_node_group_subnets" {
    value = var.serverless_node_group_subnets
}

output "ec2_elasticsearch_instances" {
    value = var.ec2_elasticsearch_instances
}

output "ec2_subnet_map" {
    value = var.ec2_subnet_map
}

output "efs_mount_point" {
    value = var.efs_mount_point
}

output "efs_mount_target_subnets" {
    value = var.efs_mount_target_subnets
}

/*output "full_dns_lookup" {
    value = var.full_dns_lookup
}*/

output "eks_console_role_arn" {
    value = var.eks_console_role_arn
}

output "eks_cluster_version" {
    value = var.eks_cluster_version
}

output "enable_rds" {
  value = var.enable_rds
}

output "enable_datahub" {
  value = var.enable_datahub
}

output "enable_keys_module" {
  value = var.enable_keys_module
}

output "ebs_encryption_by_default" {
  value = var.enable_ebs_encryption_by_default
}

output "hostedzone" {
    value = var.hostedzone
}

output "access_secret" {
    value = var.access_secret
}

output "ssh_private_key_path" {
    value = var.ssh_private_key_path
}

output "ebs_volume_size_map" {
    value = var.ebs_volume_size_map
}

output "ebs_volume_type_map" {
    value = var.ebs_volume_type_map
}

output "deployment_user" {
    value = var.deployment_user
}

output "alb_registry_image" {
    value = var.alb_registry_image
}

output "alb_controller_image_tag" {
    value = var.alb_controller_image_tag
}

output "alb_chart_version" {
    value = var.alb_chart_version
}

output "s3prefix" {
    value = var.s3prefix
}

output "ecr_repository_name" {
    value = var.ecr_repository_name
}

output "ebs_delete_on_termination" {
    value = var.ebs_delete_on_termination
}

output "efs_mongo_mount_point" {
    value = var.efs_mongo_mount_point
}

output "efs_shared_performance_mode" {
    value = var.efs_shared_performance_mode
}

output "efs_mongo_performance_mode" {
    value = var.efs_mongo_performance_mode
}


output "efs_shared_throughput_mode" {
    value = var.efs_shared_throughput_mode
}

output "efs_shared_throughput_in_mibps" {
    value = var.efs_shared_throughput_in_mibps
}

output "efs_mongo_throughput_mode" {
    value = var.efs_mongo_throughput_mode
}

output "efs_mongo_throughput_in_mibps" {
    value = var.efs_mongo_throughput_in_mibps
}

output "rds_subnets" {
    value = var.rds_subnets
}

output "rds_backup_retention_period" {
    value = var.rds_backup_retention_period
}

output "is_fresh_installation" {
    value = var.is_fresh_installation
}

output "s3_artifacts_bucket" {
    value = var.s3_artifacts_bucket
}

output "zontal_release_version" {
    value = var.zontal_release_version
}

output "domain_name" {
    value = var.domain_name
}

output "repository_pypi_name" {
    value = var.repository_pypi_name
}

output "repository_pypi_description" {
    value = var.repository_pypi_description
}

output "enable_vpc_endpoint" {
  value = var.enable_vpc_endpoint
}

output "vpc_endpoint_list" {
  value = var.vpc_endpoint_list
}

output "route_tables" {
    value =var.route_tables
}

output "internal_deployment" {
    value = var.internal_deployment
}

module "config" {
    source = "../config"
}

resource "aws_db_subnet_group" "private" {
    # Conditionally based on feature flag
    count = module.config.enable_rds == true ? 1 : 0
    name = "private_subnet_group_rds_${module.config.envname}"
    subnet_ids = toset([for i in module.config.rds_subnets : module.config.subnets[i]])

    tags = {
        Name = "private_subnet_group_rds_${module.config.envname}"
    }
}

resource "aws_db_instance" "pgsql" {
    # Conditionally based on feature flag
    count = module.config.enable_rds == true ? 1 : 0
    allocated_storage = 50
    db_subnet_group_name = aws_db_subnet_group.private[0].name
    engine = "postgres"
    engine_version = "14.7"
    instance_class = module.config.rds_instance_type
    db_name = "zontal"
    identifier = "zontal-${module.config.envname}"
    username = "zontal"
    password = module.config.rds_password
    kms_key_id = var.zontal_kms_arn
    storage_encrypted  = true
   #availability_zone = module.config.subnet_zone_a_az
    vpc_security_group_ids = [var.sg.id]
#development only
    skip_final_snapshot = true
    backup_retention_period = module.config.rds_backup_retention_period
    apply_immediately = true
#end development only features
    tags = {
        Name = "zontal-${module.config.envname}"
    }
}

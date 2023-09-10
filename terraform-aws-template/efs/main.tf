module "config" {
    source = "../config"
}

resource "aws_efs_file_system" "efs" {
#efs name need to be changed for new one
  creation_token = "ZONTAL-SHARE-${module.config.envname}"
  encrypted = true
  tags = {
    Name = "ZONTAL-SHARE-${module.config.envname}"
  }
  # generalPurpose or maxIO
  performance_mode = "${module.config.efs_shared_performance_mode}"
  # bursting or provisioned
  throughput_mode = "${module.config.efs_shared_throughput_mode}"
  provisioned_throughput_in_mibps = "${module.config.efs_shared_throughput_in_mibps}"
}


resource "aws_efs_mount_target" "mount_targets" {
  for_each = toset([for s in module.config.efs_mount_target_subnets : tostring(s)])
  file_system_id = aws_efs_file_system.efs.id
  subnet_id  = module.config.subnets[each.key]
  security_groups = [var.sg.id]
}

resource "aws_efs_file_system" "efs-mongo" {
  #efs name need to be changed for new one
  creation_token = "ZONTAL-SHARE-${module.config.envname}-mongo"
  encrypted = true
  tags = {
    Name = "ZONTAL-SHARE-${module.config.envname}-mongo"
  }
  # generalPurpose or maxIO
  performance_mode = "${module.config.efs_mongo_performance_mode}"
  # bursting or provisioned
  throughput_mode = "${module.config.efs_mongo_throughput_mode}"
  provisioned_throughput_in_mibps = "${module.config.efs_mongo_throughput_in_mibps}"
}

resource "aws_efs_mount_target" "mount_targets-mongo" {
  for_each = toset([for s in module.config.efs_mount_target_subnets : tostring(s)])
  file_system_id = aws_efs_file_system.efs-mongo.id
  subnet_id  = module.config.subnets[each.key]
  security_groups = [var.sg.id]
}
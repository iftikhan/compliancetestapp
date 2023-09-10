module "config" {
    source = "../config"
}

locals {
  serverless_node_group_subnet_ids = join(",", [for i in module.config.serverless_node_group_subnets: module.config.subnets[i]])
  eks_node_group_subnets = join(",", [for i in module.config.eks_node_group_subnets: module.config.subnets[i]])
  additional_tags = { Stoppable = "always" }
}

resource "aws_iam_instance_profile" "eks_manager" {
##change required for new ec2 inst, make sure the eks manager name is different
    name = "zontal_application_manager_${module.config.envname}"
    role = var.manager_iam.name
}

data "aws_caller_identity" "current" {}

data "external" "centos8_ami" {
  ##use this for arm64-based instance types (any type that includes a 'g' in the family name, like m6g.large)
  ##program = ["bash", "scripts/get_centos8_ami.sh", "arm64"]
  ##standard instance types
  program = ["bash", "scripts/get_centos8_ami.sh", "x86_64"]
}
resource "aws_instance" "manager" {
    ami = data.external.centos8_ami.result.id
    key_name = module.config.keypair_name
    subnet_id = module.config.subnets[module.config.ec2_subnet_map["manager"]]
    vpc_security_group_ids = [var.sg.id, var.sg_public.id]
    instance_type = module.config.ec2_manager_instance_type
    iam_instance_profile = aws_iam_instance_profile.eks_manager.name
    monitoring = true
    disable_api_termination = false
    ebs_optimized = false
    hibernation = false
    root_block_device {
        volume_size = module.config.ebs_volume_size_map["manager"]
        volume_type = module.config.ebs_volume_type_map["manager"]
        encrypted = false
        delete_on_termination = module.config.ebs_delete_on_termination
    }
    tags = module.config.internal_deployment == true ? merge(try(local.additional_tags, {}), { Name = "${module.config.envname}-manager" }) : { Name = "${module.config.envname}-manager" }

    user_data = base64encode(templatefile("ec2/userdata.tpl", {
        ADD_KUBE_AUTH_ID = var.add_kube_auth_id,
        EKS_CLUSTER_NAME = var.eks_cluster.name,
        REGION = module.config.region,
        ENV = module.config.envname,
        HOST = "manager",
        HOST_ZONE = module.config.hostedzone,
        AWS_ACCOUNT_ID = data.aws_caller_identity.current.account_id,
        EFS_ID = var.efs_id,
        EFS_MONGO_ID = var.efs_mongo_id,
        EFS_MOUNT_POINT = module.config.efs_mount_point,
        EFS_MONGO_MOUNT_POINT = module.config.efs_mongo_mount_point,
        DEPLOYMENT_USER = module.config.deployment_user,
        ALB_IAM_ARN = var.eks_worker_iam.arn,
        VPC_ID = module.config.vpc_id,
        ALB_REGISTRY_IMAGE = module.config.alb_registry_image,
        ALB_CONTROLLER_IMAGE_TAG = module.config.alb_controller_image_tag,
        ALB_CHART_VERSION = module.config.alb_chart_version,
        SM_ID = var.sm_id,
        LAMBDA_SG_ID = var.lambda_sg_id,
        ZONTAL_APPLICATION_SG_ID = var.sg.id
        SERVERLESS_NODE_GROUP_SUBNET_IDS = local.serverless_node_group_subnet_ids,
        EKS_NODE_GROUP_SUBNET_IDS = local.eks_node_group_subnets,
        KEY= module.config.ssh_private_key_path,
        ES_HOSTS = module.config.ec2_elasticsearch_instances,
        SNS_NOTIFICATION_TOPIC_ARN = var.sns_notification_topic_arn,
        SNS_NOTIFICATION_FIFO_TOPIC_ARN = var.sns_notification_fifo_topic_arn
		SQS_NOTIFICATION_FIFO_QUEUE_URL = var.sqs_notification_fifo_queue_url
        SQS_TRANSITIONS_RETRY_URL = var.sqs_transitions_retry_url
        SQS_TRANSITIONS_RETRY_ARN = var.sqs_transitions_retry_arn
        SNS_TRANSITIONS_FAILURE_TOPIC_ARN = var.sns_transitions_failure_topic_arn
        ACCESS_SECRET = base64encode(module.config.access_secret)
        EKS_CLUSTER_SECURITY_GROUP_ID = var.eks_cluster_security_group_id
        RDS_HOSTNAME = var.rds.hostname
        RDS_PORT = var.rds.port
        RDS_DB_NAME = var.rds.db_name
        RDS_PASSWORD = module.config.rds_password
        }))
    connection {
        type        = "ssh"
        user        = module.config.deployment_user
        private_key = "${file("${module.config.ssh_private_key_path}")}"
        timeout     = "3m"
        host        = self.private_ip
      }

    provisioner "file" {
      source      = "rpm/ansible-2.9.27-3.el8.noarch.rpm"
      destination = "/tmp/ansible-2.9.27-3.el8.noarch.rpm"
      }
    provisioner "file" {
      source      = "scripts/serverless.sh"
      destination = "/tmp/serverless.sh"
      }
    provisioner "file" {
      source      = "scripts/serverless-linux-x64"
      destination = "/tmp/serverless-linux-x64"
      }


    provisioner "remote-exec" {
     inline = [
       "curl -o kubectl https://s3.us-west-2.amazonaws.com/amazon-eks/1.24.7/2022-10-31/bin/linux/amd64/kubectl",
       "chmod +x ./kubectl",
       "mkdir -p $HOME/bin && cp ./kubectl $HOME/bin/kubectl && export PATH=$PATH:$HOME/bin",
       "echo 'export PATH=$PATH:$HOME/bin' >>~/.bashrc",
     ]
    }
    lifecycle {
      ignore_changes = [ami]
    }
}

resource "aws_route53_record" "zontal" {
  zone_id = var.zone_id
  name    = "manager.${module.config.envname}.${module.config.hostedzone}"
  type    = "A"
  ttl     = "300"
  records = [aws_instance.manager.private_ip]
}

resource "aws_instance" "elasticsearch" {
    ami = data.external.centos8_ami.result.id
##this list length determines how many instances are created
    for_each = toset(module.config.ec2_elasticsearch_instances)
    key_name = module.config.keypair_name
    subnet_id = module.config.subnets[module.config.ec2_subnet_map[each.key]]
    vpc_security_group_ids = [var.sg.id]
    instance_type = module.config.ec2_elasticsearch_instance_type
    monitoring = true
    disable_api_termination = false
    ebs_optimized = false
    hibernation = false
    root_block_device {
        volume_size = module.config.ebs_volume_size_map[each.key]
        volume_type = module.config.ebs_volume_type_map[each.key]
        encrypted = false
        delete_on_termination = module.config.ebs_delete_on_termination
    }
    tags = module.config.internal_deployment == true ? merge(try(local.additional_tags, {}), { Name = "${module.config.envname}-${each.key}" }) : { Name = "${module.config.envname}-${each.key}" }
    user_data = base64encode(templatefile("ec2/elasticdata.tpl", {
        REGION = module.config.region,
        ENV = module.config.envname,
        HOST= each.key,
        HOST_ZONE = module.config.hostedzone,
        EFS_ID = var.efs_id,
        EFS_MOUNT_POINT = module.config.efs_mount_point,
        DEPLOYMENT_USER = module.config.deployment_user
        }))
    lifecycle {
      ignore_changes = [ami]
    }
}

resource "aws_route53_record" "es_node" {
  for_each = toset(module.config.ec2_elasticsearch_instances)
  zone_id = var.zone_id
  name    = "${each.key}.${module.config.envname}.${module.config.hostedzone}"
  type    = "A"
  ttl     = "300"
  records = [aws_instance.elasticsearch[each.key].private_ip]
}

resource "null_resource" "generate_ssh_idrsa" {
# tries to generate id_rsa and pub key when you first login to an instance
    provisioner "local-exec" {
        command =  "echo -e 'y\n'| ssh-keygen -q -f /home/`whoami`/.ssh/id_rsa -t rsa -N ''"
        }
    depends_on = [aws_instance.manager]
}

resource "null_resource" "create-ssh-config" {
# create ssh config file in functional user "ec2-user" home path
    provisioner "local-exec" {
        command = <<EOD
cat <<EOF | tee ~/.ssh/config
Host manager.${module.config.envname}.${module.config.hostedzone}
  HostName manager.${module.config.envname}.${module.config.hostedzone}
  User ${module.config.deployment_user}
  IdentityFile ${module.config.ssh_private_key_path}
EOF
EOD
    }
    depends_on = [null_resource.generate_ssh_idrsa]
}
resource "null_resource" "change-config-permission" {
# config permission is stricted
    provisioner "local-exec" {
        command = "chmod 600 /home/`whoami`/.ssh/config"
        }
    depends_on = [null_resource.create-ssh-config]
}
resource "null_resource" "accept_ssh_hostkey_hostname" {
# tries to remove the "accept hostkey" prompt that ssh gives when you first login to an instance
    provisioner "local-exec" {
        command = "sleep 120  && ssh-keyscan -H manager.${module.config.envname}.${module.config.hostedzone} >> /home/`whoami`/.ssh/known_hosts"
        }
    depends_on = [null_resource.change-config-permission]
}

resource "null_resource" "add_ssh" {
## copies the local ssh key from terraform onto the installation machine
    provisioner "local-exec" {
        command = "scp  ${module.config.ssh_private_key_path} ${module.config.deployment_user}@manager.${module.config.envname}.${module.config.hostedzone}:/home/${module.config.deployment_user}/.ssh/"
    }
    depends_on = [null_resource.accept_ssh_hostkey_hostname]
}

resource "null_resource" "download_ansible_package" {
# download ansible instalation package to local
    # Conditionally based on fresh installation flag
    count = module.config.is_fresh_installation == true ? 1 : 0
    provisioner "local-exec" {
        command = "aws s3 cp s3://${module.config.s3_artifacts_bucket}/zontal/deployment/space-deployment/${module.config.zontal_release_version}/space-deployment-${module.config.zontal_release_version}.tar.gz /home/`whoami`/space-deployment-${module.config.zontal_release_version}.tar.gz"
    }
    depends_on = [null_resource.add_ssh]
}

resource "null_resource" "transfer_ansible_package_to_manager_host" {
# transfer ansible installation package to manager host
    # Conditionally based on fresh installation flag
    count = module.config.is_fresh_installation == true ? 1 : 0
    provisioner "local-exec" {
        command = "scp /home/`whoami`/space-deployment-${module.config.zontal_release_version}.tar.gz ${module.config.deployment_user}@manager.${module.config.envname}.${module.config.hostedzone}:/home/${module.config.deployment_user}/"
    }
    depends_on = [null_resource.download_ansible_package]
}

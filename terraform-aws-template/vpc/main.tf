module "config" {
  source = "../config/"
}


resource "aws_security_group" "zontal_app_sg" {
    name = "ZONTAL_APPLICATION_SG_${module.config.envname}"
    description = "allows communication between components of the ZONTAL Space platform"
    vpc_id = module.config.vpc_id
    ingress {
        description = "Access within ZONTAL Nodes"
        from_port = 0
        to_port = 65535
        protocol = "tcp"
        self = true
        cidr_blocks = [module.config.vpc_cidr_block]
    }
     ingress {
        description = "Access ALB from zontal network"
        from_port = 443
        to_port = 443
        protocol = "tcp"
        self = true
        cidr_blocks = ["172.16.0.0/16"]
    }
    ingress {
        description = "Access ALB from zontal network"
        from_port = 443
        to_port = 443
        protocol = "tcp"
        self = true
        cidr_blocks = ["172.16.0.0/16"]
    }
    ingress {
        description = "DNS"
        from_port = 53
        to_port = 53
        protocol = "udp"
        self = true
        cidr_blocks = [module.config.vpc_cidr_block]
    }
    ingress {
        description = "Healthchecks"
        from_port = -1
        to_port = -1
        protocol = "icmp"
        self = true
        cidr_blocks = [module.config.vpc_cidr_block]
    }
    ingress {
        description = "TF Management Access"
        from_port = 22
        to_port = 22
        protocol = "tcp"
#terraform machine only
        cidr_blocks = [module.config.terraform_machine_cidr_range]
    }
    egress {
        description = "Traffic originating from the node is allowed through"
        from_port = 0
        to_port = 0
        protocol = "-1"
        cidr_blocks = ["0.0.0.0/0"]
        ipv6_cidr_blocks = ["::/0"]
    }
    tags = {
        Name = "ZONTAL_APPLICATON_SG_${module.config.envname}"
        "kubernetes.io/cluster/ZONTAL-EKS-CLUSTER-${module.config.envname}" = "owned"
    }
}

resource "aws_security_group" "lambda_sg" {
  name   = "${module.config.envname}-platform-lambdaSg"
  description = "Allows all outgoing traffic for lambda function part of the platform"
  vpc_id = module.config.vpc_id

  egress {
      description = "Traffic originating from the lambda is allowed through"
      from_port = 0
      to_port = 0
      protocol = "-1"
      cidr_blocks = ["0.0.0.0/0"]
      ipv6_cidr_blocks = ["::/0"]
  }
  tags = {
    Name          = "${module.config.envname}-${module.config.envdomain}-lambdaSg"
    "kubernetes.io/cluster/ZONTAL-EKS-CLUSTER-${module.config.envname}" = "owned"
    "zontal:env"    = "${module.config.envname}"
    "zontal:domain" = "${module.config.envdomain}"
    "zontal:type"   = "lambdaSg"
  }
}


resource "aws_security_group" "zontal_app_public_sg" {
    name = "ZONTAL_APP_PUB_SG_${module.config.envname}"
    description = "Allows access to the ZONTAL SPACE WebUI"
    vpc_id = module.config.vpc_id
    ingress {
        description = "HTTP to HTTPS redirect"
        from_port = 80
        to_port = 80
        protocol = "tcp"
        self = true
        cidr_blocks = ["0.0.0.0/0"]
    }
    ingress {
        description = "HTTPS"
        from_port = 443
        to_port = 443
        protocol = "tcp"
        self = true
        cidr_blocks = ["0.0.0.0/0"]
    }
    egress {
        description = "Traffic originating from the node is allowed through"
        from_port = 0
        to_port = 0
        protocol = "-1"
        cidr_blocks = ["0.0.0.0/0"]
        ipv6_cidr_blocks = ["::/0"]
    }
    tags = {
        Name = "ZONTAL_APP_PUB_SG_${module.config.envname}"
        "kubernetes.io/cluster/ZONTAL-EKS-CLUSTER-${module.config.envname}" = "owned"
    }
}

################################################################################
# VPC Endpoint(s)
################################################################################

# Create Security Group which is used by Endpoint
resource "aws_security_group" "vpc_endpoint_sg" {
  count = module.config.enable_vpc_endpoint == true ? 1 : 0

  name        = "ZONTAL_VPC_ENDPOINT_SG_${module.config.envname}"
  description = "Allows access to the ZONTAL SPACE WebUI"
  vpc_id      = module.config.vpc_id

  ingress {
    description      = "Allow all to access VPC Endpoint"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    self             = true
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
  egress {
    description      = "Traffic originating from the VPC Endpoint is allowed through"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
  tags = {
    Name = "ZONTAL_VPC_ENDPOINT_SG_${module.config.envname}"
  }
}

locals {
  vpc_endpoints = { for k, v in module.config.vpc_endpoint_list : k => v if module.config.enable_vpc_endpoint }
}

# retrieve endpoint service name, i.e. com.amazonaws.eu-central-1.s3
data "aws_vpc_endpoint_service" "this" {
  for_each = local.vpc_endpoints

  service = try(each.key, null)

  filter {
    name   = "service-type"
    values = [each.value] # would be Interface or Gateway
  }
}

resource "aws_vpc_endpoint" "this" {
  for_each = local.vpc_endpoints

  vpc_id            = module.config.vpc_id
  service_name      = data.aws_vpc_endpoint_service.this[each.key].service_name
  vpc_endpoint_type = each.value

  tags = {
    # It is showed as endpoint name in the console
    Name = "${module.config.envname}_${each.key}_endpoint"
  }

  # configuration for Interface endpoint
  security_group_ids  = each.value == "Interface" ? [aws_security_group.vpc_endpoint_sg[0].id] : null
  subnet_ids          = each.value == "Interface" ? module.config.subnets : null
  private_dns_enabled = each.value == "Interface" ? true : null

  # configuration for Gateway endpoint
  route_table_ids = each.value == "Gateway" ? module.config.route_tables : null
}

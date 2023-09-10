#route 53 hosted zone and records for nasa2
module "config" {
    source = "../config"
}
resource "aws_route53_zone" "rt53zone" {
  name = module.config.hostedzone
  vpc {
    vpc_id = module.config.vpc_id
  }
  comment = "Managed by Terraform for ${module.config.envname}"
}

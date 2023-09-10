#secret manager for lambda function
module "config" {
    source = "../config"
}
resource "aws_secretsmanager_secret" "space-client-secret" {
    name = "${module.config.envdomain}-${module.config.envname}-secret"
    recovery_window_in_days = 0
    tags = {
        Name = "${module.config.envname}-client-secret"
    }
}

locals {
  # secret to pass to aws_secretsmanager_secret_version
  secret_string = {
    "application-client-secret" = "${module.config.access_secret}"
    "machine-client-secret" = "${module.config.access_secret}"
    "dns-name" = format("%s.%s","${module.config.envname}","${module.config.hostedzone}")
  }
}

resource "aws_secretsmanager_secret_version" "secret-version" {
  secret_id     = aws_secretsmanager_secret.space-client-secret.id
  secret_string = jsonencode(local.secret_string)
}

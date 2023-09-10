module "config" {
    source = "../config"
}

resource "aws_ebs_encryption_by_default" "ebsenc" {
    # Conditionally based on feature flag
    count = module.config.enable_keys_module == true ? 1 : 0
    enabled = module.config.enable_ebs_encryption_by_default
}

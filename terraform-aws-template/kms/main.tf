 module "config" {
   source = "../config"
 }
data "aws_caller_identity" "current" {
}
locals {
  account_id = data.aws_caller_identity.current.account_id
}
output "account_id" {
  value = local.account_id
}

data "aws_iam_policy_document" "zontal_custom_key" {
  #checkov:skip=CKV_AWS_109:Warning
  #checkov:skip=CKV_AWS_111:Warning
  statement {
    sid       = "Enable IAM User Permissions"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }
}
resource "aws_kms_key" "zontal_custom_kms" {
  description              = "Custome KMS key for zontal"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  is_enabled               = true
  enable_key_rotation      = true
  policy                   = data.aws_iam_policy_document.zontal_custom_key.json
}

# Add an alias to the key
resource "aws_kms_alias" "zontal_cmk_alias" {
  name          = "alias/zontal_custom_kms_${module.config.envname}"
  target_key_id = aws_kms_key.zontal_custom_kms.key_id
}
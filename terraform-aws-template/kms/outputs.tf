output "zontal_kms_id" {
  value = aws_kms_key.zontal_custom_kms.key_id
}

output "zontal_kms_arn" {
  value = aws_kms_key.zontal_custom_kms.arn
}
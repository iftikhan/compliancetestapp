output "sm_id" {
    value = aws_secretsmanager_secret.space-client-secret.id
}

output "sm_arn" {
  value = aws_secretsmanager_secret.space-client-secret.arn
}
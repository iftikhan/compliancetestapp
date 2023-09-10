output "efs_id" {
  value = aws_efs_file_system.efs.id
}

output "efs_mongo_id" {
  value = aws_efs_file_system.efs-mongo.id
}
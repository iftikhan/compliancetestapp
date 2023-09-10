output "rds" {
  value = {
      hostname = try(element(aws_db_instance.pgsql.*.address,0), "")
      port = try(element(aws_db_instance.pgsql.*.port,0), "")
      db_name = try(element(aws_db_instance.pgsql.*.db_name,0), "")
  }
}

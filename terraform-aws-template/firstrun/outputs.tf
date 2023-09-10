output "Dynamo_DB_Table" {
    value = aws_dynamodb_table.terraform_statelock.name
}

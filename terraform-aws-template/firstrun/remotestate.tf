module "config" {
    source = "../config"
}
provider "aws" {
  region  = module.config.region
}

resource "aws_dynamodb_table" "terraform_statelock" {
  name = "terraformf-remote-state-lock-${module.config.envname}"
  read_capacity = 20
  write_capacity = 20
  hash_key = "LockID"

  attribute {
      name = "LockID"
      type = "S"
  }
}

variable "domain_name" {
  type = string
}

variable "repository_pypi_name" {
  type = string
}

variable "repository_pypi_description" {
  type = string
}

variable "manager_iam" {
  type = object({
    name = string
    arn = string
  })
}

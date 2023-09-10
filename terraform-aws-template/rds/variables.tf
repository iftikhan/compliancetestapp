variable "sg" {
    type = object({
        name = string
        id = string
    })
}

variable "subnets" {
    type = list(string)
}
variable "zontal_kms_arn" {
  type = string
}
variable "sg" {
    type = object({
        name = string
        id = string
    })
}

variable "subnets" {
    type = list(string)
}
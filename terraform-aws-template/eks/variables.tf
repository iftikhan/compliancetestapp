variable "sg" {
    type = object({
        name = string
        id = string
    })
}

variable "subnets" {
    type = list(string)
}

variable "efs_id" {
    type = string
}

variable "efs_mongo_id" {
    type = string
}

variable "sns_notification_fifo_topic_arn" {
    type = string
}

variable "sqs_transitions_retry_url" {
    type = string
}

variable "sqs_transitions_retry_arn" {
    type = string
}

variable "sns_transitions_failure_topic_arn" {
     type = string
}

variable "sns_notification_topic_arn" {
    type = string
}

variable "sqs_notification_fifo_queue_arn" {
    type = string
}

variable "sm_arn" {
  type = string
}
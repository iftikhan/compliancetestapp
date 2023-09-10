variable "subnets" {
    type = list(string)
}
variable "sg" {
    type = object({
        name = string
        id = string
    })
}
variable "sg_public" {
    type = object({
        name = string
        id = string
    })
}

variable "efs_id" {
    type = string
}

variable "eks_worker_iam" {
    type = object({
        name = string
        arn = string
    })
}

variable "manager_iam" {
    type = object({
        name = string
        arn = string
    })
}

variable "eks_cluster_iam" {
    type = object({
        name = string
        arn = string
    })
}

variable "eks_cluster" {
    type = object({
        name = string
        arn = string
    })
}

variable "zone_id" {
    type = string
}

variable "sm_id" {
    type = string
}

variable "lambda_sg_id" {
    type = string
}

variable "sns_notification_topic_arn" {
    type = string
}

variable "sns_notification_fifo_topic_arn" {
    type = string
}
          
variable "sqs_notification_fifo_queue_url" {
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

variable "rds" {
    type = object({
        hostname = string
        port = string
        db_name = string
    })
}

variable "eks_cluster_security_group_id" {
    type = string
}

# just to make sure the module.eks.null_resource.add_kube_auth execution completed updating kube authmap
# since the authmap is the dependency for aws_instance.manager user-data initialization script(kubectl apply ..)
variable "add_kube_auth_id" {
  type = string
}

variable "efs_mongo_id" {
    type = string
}
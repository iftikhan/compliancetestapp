module "config" {
    source = "../config"
}

resource "aws_sqs_queue" "space-notification-ais-sqs-fifo" {
  name                        = "space-common-notifications-${module.config.envname}-spaceNotification-ais-sqsQueue.fifo"
  fifo_queue                  = true
  content_based_deduplication = true
  kms_data_key_reuse_period_seconds = 43200
  tags = {
      Name = "${module.config.envname}-space-notification-ais-sqs.fifo"
    }
  #deduplication_scope = messageGroup
  #fifo_throughput_limit = perMessageGroupId
  #delay_seconds: 0
  #visibility_timeout: 300
}

				
# Subscribe the SQS queue to the SNS topic
resource "aws_sns_topic_subscription" "sns-topic" {
  topic_arn = var.sns_notification_fifo_topic_arn
  protocol  = "sqs"
  endpoint  = var.sqs_notification_fifo_queue_arn
  filter_policy = <<POLICY
{
      "transitionStatus" : [
              "http://purl.zontal.io/codelists/space/transition-status#SubmissionCompleted",
              "http://purl.zontal.io/codelists/space/transition-status#SubmissionAborted",
              "http://purl.zontal.io/codelists/space/transition-status#PurgeCompleted"
          ],
          "function": [
             "ingest"
           ]
}
POLICY
}

resource "aws_sqs_queue" "space-transitions-retry-queue-fifo" {
  name                          = "${module.config.envname}-space-transitions-retry-queue.fifo"
  fifo_queue                    = true
  content_based_deduplication   = true
  delay_seconds                 = 900 # The time in seconds that the delivery of all messages in the queue will be delayed. 
  message_retention_seconds     = 345600 # (Optional) The number of seconds Amazon SQS retains a message. Integer representing seconds, from 60 (1 minute) to 1209600 (14 days). The default for this attribute is 345600 (4 days).
  receive_wait_time_seconds     = 20 # (Optional) The time for which a ReceiveMessage call will wait for a message to arrive (long polling) before returning.
  kms_data_key_reuse_period_seconds = 43200
  tags = {
    Name = "${module.config.envname}-space-transitions-retry-queue.fifo"
  }
}

resource "aws_sqs_queue_policy" "sqs_queue_policy" {
  queue_url = var.sqs_notification_fifo_queue_id
  policy    = data.aws_iam_policy_document.ais_sqs_queue_policy_document.json
  }

data "aws_iam_policy_document" "ais_sqs_queue_policy_document" {
  statement {
      effect = "Allow"
      resources = [aws_sqs_queue.space-notification-ais-sqs-fifo.arn]
      actions = [
        "SQS:AddPermission",
        "SQS:DeleteMessage",
        "SQS:GetQueueUrl",
        "SQS:SendMessage",
        "SQS:ChangeMessageVisibility",
        "SQS:ReceiveMessage",
        "SQS:RemovePermission"
      ]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    }
}

output "aws_platform_sqs_notification_fifo_queue_url" {
    value = aws_sqs_queue.space-notification-ais-sqs-fifo.url
}
output "aws_platform_sqs_notification_fifo_queue_arn" {
    value = aws_sqs_queue.space-notification-ais-sqs-fifo.arn
}

output "aws_platform_sqs_notification_fifo_queue_id" {
    value = aws_sqs_queue.space-notification-ais-sqs-fifo.id
}

output "aws_platform_sqs_transitions_retry_url" {
  value = aws_sqs_queue.space-transitions-retry-queue-fifo.url
}

output "aws_platform_sqs_transitions_retry_arn" {
  value = aws_sqs_queue.space-transitions-retry-queue-fifo.arn
}


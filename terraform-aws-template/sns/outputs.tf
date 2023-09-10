output "aws_platform_sns_notification_topic_arn" {
    value = aws_sns_topic.space-notification.arn
}

output "aws_platform_sns_notification_fifo_topic_arn" {
    value = aws_sns_topic.space-notification-fifo.arn
}

output "aws_platform_sns_transitions_failure_topic_arn" {
    value = aws_sns_topic.space-transitions-failure.arn
}
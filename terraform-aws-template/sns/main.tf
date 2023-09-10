module "config" {
    source = "../config"
}
resource "aws_sns_topic" "space-notification" {
    name = "${module.config.envname}-space-notification"
    tags = {
        Name = "${module.config.envname}-space-notification"
    }
}

resource "aws_sns_topic" "space-notification-fifo" {
  name                        = "space-common-notifications-${module.config.envname}-spaceNotification-snsTopic.fifo"
  fifo_topic                  = true
  content_based_deduplication = true
  tags = {
      Name = "${module.config.envname}-space-notification.fifo"
    }
}

resource "aws_sns_topic" "space-transitions-failure" {
    name = "${module.config.envname}-space-transitions-failure"
    tags = {
        Name = "${module.config.envname}-space-transitions-failure"
    }
}

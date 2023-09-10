module "config" {
    source = "../config"
}
data "aws_caller_identity" "current" {}
locals {
    account_id = data.aws_caller_identity.current.account_id
    alb-account-id = "054676820928" #valid account id for Region eu-central-1. Full list -> https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html
}

output "account_id" {
  value = local.account_id
}

resource "aws_s3_bucket" "ingest" {
    bucket = "${module.config.envname}-zontal-ingest"
    #force destroy to allow terraform to delete buckets even if they are not empty
    force_destroy = true
    tags = {
        Name = "${module.config.envname}-zontal-ingest"
    }
}

resource "aws_s3_bucket_ownership_controls" "ingest_own_ctrl" {
  bucket = aws_s3_bucket.ingest.id

  rule {
    object_ownership = "ObjectWriter"
  }
}

resource "aws_s3_bucket_acl" "ingest" {
  bucket = aws_s3_bucket.ingest.id
  acl    = "private"

  depends_on = [aws_s3_bucket_ownership_controls.ingest_own_ctrl]
}

resource "aws_s3_bucket_policy" "alb_access_log" { 
    bucket= "${aws_s3_bucket.ingest.id}"
    policy =<<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${local.alb-account-id}:root"
      },
      "Action": "s3:PutObject",
      "Resource": "${aws_s3_bucket.ingest.arn}/${module.config.s3prefix}/AWSLogs/${local.account_id}/*"
    },
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "delivery.logs.amazonaws.com"
      },
      "Action": "s3:PutObject",
      "Resource": "${aws_s3_bucket.ingest.arn}/${module.config.s3prefix}/AWSLogs/${local.account_id}/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control"
        }
      }
    },
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "delivery.logs.amazonaws.com"
      },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::${module.config.envname}-zontal-ingest"
    }
   ]
  }
POLICY
}
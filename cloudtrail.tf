resource "aws_cloudwatch_log_group" "alb_controller_cloudtrail_logs" {
  count = var.enable_cloudtrail_logging ? 1 : 0
  name  = "alb_controller-cloudtrail-logs-${var.cluster_name}"
}

data "aws_iam_policy_document" "cloudtrail-assume-role-policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}


resource "random_string" "role_suffix" {
  length  = 5
  special = false
}


resource "aws_s3_bucket" "alb_controller_cloudtrail_logs" {

  count  = var.enable_cloudtrail_logging ? 1 : 0
  bucket =  "alb-controller-cloudtrail-logs-${var.cluster_name}"
  

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::alb-controller-cloudtrail-logs-${var.cluster_name}"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::alb-controller-cloudtrail-logs-${var.cluster_name}/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
POLICY
}



resource "aws_iam_role" "cloudtrail_to_cloudwatch" {
  count = var.enable_cloudtrail_logging ? 1 : 0
  name  = "CloudWatchWriteForCloudTrail-${random_string.role_suffix.result}"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  assume_role_policy = data.aws_iam_policy_document.cloudtrail-assume-role-policy.json
  inline_policy {
    name = "cloudwatch_write_permissions"

    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action = [
            "cloudwatch:PutMetricData",
            "logs:PutLogEvents",
            "logs:DescribeLogStreams",
            "logs:DescribeLogGroups",
            "logs:CreateLogStream",
            "logs:CreateLogGroup"
          ]
          Effect   = "Allow"
          Resource = "*"
        },
      ]
    })
  }
}


resource "aws_cloudtrail" "alb_controller" {
  count                         = var.enable_cloudtrail_logging ? 1 : 0
  name                          = "alb_controller-trail"
  s3_bucket_name                = aws_s3_bucket.alb_controller_cloudtrail_logs[0].id
  s3_key_prefix                 = "trail"
  include_global_service_events = false


  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.alb_controller_cloudtrail_logs[0].arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_to_cloudwatch[0].arn
}

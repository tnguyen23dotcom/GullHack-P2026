# Task #5: email if estimated AWS charges pass a limit.
# AWS publishes billing metrics only in us-east-1, which is our region.

variable "billing_alarm_usd" {
  description = "Send an email when estimated monthly charges reach this many US dollars."
  type        = number
  default     = 10
}

# Separate topic so CloudWatch can publish to it with the default topic policy
resource "aws_sns_topic" "billing" {
  name = "${var.project}-billing-alarm"
}

resource "aws_sns_topic_subscription" "billing_email" {
  topic_arn = aws_sns_topic.billing.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_metric_alarm" "billing" {
  alarm_name          = "${var.project}-estimated-charges"
  alarm_description   = "Estimated AWS charges this month reached ${var.billing_alarm_usd} USD."
  namespace           = "AWS/Billing"
  metric_name         = "EstimatedCharges"
  dimensions          = { Currency = "USD" }
  statistic           = "Maximum"
  period              = 21600 # billing data updates every few hours
  evaluation_periods  = 1
  threshold           = var.billing_alarm_usd
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.billing.arn]
}

output "billing_alarm" {
  value = aws_cloudwatch_metric_alarm.billing.alarm_name
}
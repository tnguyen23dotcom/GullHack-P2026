# Task #4: email alerts and the alerts read endpoint

variable "alert_email" {
  description = "Email address that receives leak alerts (set in secrets.auto.tfvars)."
  type        = string
}

# SNS topic + email subscription
resource "aws_sns_topic" "alerts" {
  name = "${var.project}-leak-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EventBridge rule: catch LeakDetected events from our Lambda
resource "aws_cloudwatch_event_rule" "leak_detected" {
  name = "${var.project}-leak-detected"
  event_pattern = jsonencode({
    source        = [var.project]
    "detail-type" = ["LeakDetected"]
  })
}

resource "aws_cloudwatch_event_target" "email" {
  rule = aws_cloudwatch_event_rule.leak_detected.name
  arn  = aws_sns_topic.alerts.arn

  input_transformer {
    input_paths = {
      session = "$.detail.session_id"
      reason  = "$.detail.reason"
      alert   = "$.detail.alert_id"
    }
    input_template = "\"LEAK DETECTED: chat session <session> was blocked. Reason: <reason>. Alert ID: <alert>.\""
  }
}

# Allow only this EventBridge rule to publish to the topic
resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgeRule"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        ArnEquals = { "aws:SourceArn" = aws_cloudwatch_event_rule.leak_detected.arn }
      }
    }]
  })
}

# Lambda may send events to the default event bus
resource "aws_iam_role_policy" "events" {
  name = "${var.project}-events-policy"
  role = aws_iam_role.gateway.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "PutLeakEvents"
      Effect   = "Allow"
      Action   = "events:PutEvents"
      Resource = "arn:aws:events:${var.region}:${data.aws_caller_identity.current.account_id}:event-bus/default"
    }]
  })
}

# GET /alerts for Person D's dashboard (same Lambda)
resource "aws_apigatewayv2_route" "alerts" {
  api_id    = aws_apigatewayv2_api.chat.id
  route_key = "GET /alerts"
  target    = "integrations/${aws_apigatewayv2_integration.gateway.id}"
}

output "alerts_url" {
  value = "${aws_apigatewayv2_api.chat.api_endpoint}/alerts"
}
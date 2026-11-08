data "aws_caller_identity" "current" {}

locals {
  function_name = "${var.project}-gateway"
  account_id    = data.aws_caller_identity.current.account_id

  # A "us." inference profile routes to the foundation model in several US regions,
  # so the foundation-model ARN needs a wildcard region. Strip the geo prefix to get
  # the foundation model ID (e.g. "us.amazon.nova-2-lite-v1:0" -> "amazon.nova-2-lite-v1:0").
  foundation_model_id = replace(var.model_id, "/^(us|global|eu|apac)\\./", "")
}

# ---------- Lambda package ----------

data "archive_file" "gateway" {
  type        = "zip"
  output_path = "${path.module}/build/gateway.zip"

  # The Lambda handler (infra/lambda) goes at the root of the zip
  dynamic "source" {
    for_each = [for f in fileset("${path.module}/../lambda", "**") : f if !strcontains(f, "__pycache__")]
    content {
      content  = file("${path.module}/../lambda/${source.value}")
      filename = source.value
    }
  }

  # Person B's checks/ folder goes inside the zip as checks/
  dynamic "source" {
    for_each = [for f in fileset("${path.module}/../../checks", "**") : f if !strcontains(f, "__pycache__") && !startswith(f, "tests/")]
    content {
      content  = file("${path.module}/../../checks/${source.value}")
      filename = "checks/${source.value}"
    }
  }
}

# ---------- IAM (least privilege) ----------

data "aws_iam_policy_document" "lambda_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "gateway" {
  name               = "${local.function_name}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

data "aws_iam_policy_document" "gateway" {
  statement {
    sid       = "OwnLogsOnly"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.gateway.arn}:*"]
  }

  statement {
    sid     = "InvokeChatModelOnly"
    actions = ["bedrock:InvokeModel"]
    resources = [
      "arn:aws:bedrock:${var.region}:${local.account_id}:inference-profile/${var.model_id}",
      "arn:aws:bedrock:*::foundation-model/${local.foundation_model_id}",
    ]
  }
}

resource "aws_iam_role_policy" "gateway" {
  name   = "${local.function_name}-policy"
  role   = aws_iam_role.gateway.id
  policy = data.aws_iam_policy_document.gateway.json
}

# ---------- Lambda ----------

resource "aws_cloudwatch_log_group" "gateway" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = 7
}

resource "aws_lambda_function" "gateway" {
  function_name    = local.function_name
  role             = aws_iam_role.gateway.arn
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.gateway.output_path
  source_code_hash = data.archive_file.gateway.output_base64sha256
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      MODEL_ID  = var.model_id
      LOG_LEVEL = "INFO"
      SESSIONS_TABLE = aws_dynamodb_table.sessions.name
      ALERTS_TABLE   = aws_dynamodb_table.alerts.name
    }
  }

  depends_on = [aws_cloudwatch_log_group.gateway, aws_iam_role_policy.gateway]
}

# ---------- API Gateway (HTTP API) ----------

resource "aws_apigatewayv2_api" "chat" {
  name          = "${var.project}-api"
  protocol_type = "HTTP"

  cors_configuration {
    allow_origins = var.allowed_origins
    allow_methods = ["POST", "OPTIONS"]
    allow_headers = ["content-type", "x-session-id"]
    max_age       = 300
  }
}

resource "aws_apigatewayv2_integration" "gateway" {
  api_id                 = aws_apigatewayv2_api.chat.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.gateway.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "chat" {
  api_id    = aws_apigatewayv2_api.chat.id
  route_key = "POST /chat"
  target    = "integrations/${aws_apigatewayv2_integration.gateway.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.chat.id
  name        = "$default"
  auto_deploy = true

  # Light throttling caps cost if the URL leaks.
  default_route_settings {
    throttling_burst_limit = 10
    throttling_rate_limit  = 5
  }
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowApiGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.gateway.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.chat.execution_arn}/*/*"
}

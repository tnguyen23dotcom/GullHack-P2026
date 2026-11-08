# Sessions: one row per chat session, holding its canary (issue #2)
resource "aws_dynamodb_table" "sessions" {
  name         = "${var.project}-sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "session_id"

  attribute {
    name = "session_id"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
}

# Alerts: one row per detected leak, grouped by session (issue #2, used by #3/#4)
resource "aws_dynamodb_table" "alerts" {
  name         = "${var.project}-alerts"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "session_id"
  range_key    = "alert_id"

  attribute {
    name = "session_id"
    type = "S"
  }

  attribute {
    name = "alert_id"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
}

# Lambda may only read/write these two tables
resource "aws_iam_role_policy" "dynamodb" {
  name = "${var.project}-dynamodb-policy"
  role = aws_iam_role.gateway.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "SessionsReadWrite"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"]
        Resource = aws_dynamodb_table.sessions.arn
      },
      {
        Sid      = "AlertsWriteRead"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem", "dynamodb:Query"]
        Resource = aws_dynamodb_table.alerts.arn
      }
    ]
  })
}

output "sessions_table" {
  value = aws_dynamodb_table.sessions.name
}

output "alerts_table" {
  value = aws_dynamodb_table.alerts.name
}
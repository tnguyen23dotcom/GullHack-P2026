output "chat_url" {
  description = "POST {session_id, message} here. Give this URL to Person D for the web UI."
  value       = "${aws_apigatewayv2_api.chat.api_endpoint}/chat"
}

output "lambda_name" {
  value = aws_lambda_function.gateway.function_name
}

output "log_group" {
  value = aws_cloudwatch_log_group.gateway.name
}

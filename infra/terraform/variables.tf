variable "region" {
  description = "AWS region for every resource."
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Name prefix for resources and the Project tag."
  type        = string
  default     = "canary-gateway"
}

variable "model_id" {
  description = "Bedrock chat model as a cross-region inference profile ID (starts with \"us.\"). Amazon Nova 2 Lite works on the AWS Free plan; Claude models (e.g. us.anthropic.claude-haiku-5-5) need a Paid plan. Confirm with `aws bedrock list-inference-profiles`."
  type        = string
  default     = "us.amazon.nova-2-lite-v1:0"
}

variable "allowed_origins" {
  description = "CORS origins allowed to call the chat API. Narrow this to the CloudFront URL once the web UI is deployed."
  type        = list(string)
  default     = ["*"]
}

#!/usr/bin/env bash
# One-command deploy for the canary gateway (issue #5).
# Usage, from the repo root:   ./infra/deploy.sh
# Skip the confirmation:       ./infra/deploy.sh --auto-approve
set -euo pipefail

TF_DIR="$(cd "$(dirname "$0")" && pwd)/terraform"

for cmd in terraform aws; do
  command -v "$cmd" >/dev/null || { echo "'$cmd' is not installed or not on PATH."; exit 1; }
done

echo "Checking AWS login..."
ACCOUNT=$(aws sts get-caller-identity --query Account --output text) \
  || { echo "AWS CLI is not logged in. Run 'aws configure' first."; exit 1; }
echo "Deploying to AWS account $ACCOUNT"

if [[ ! -f "$TF_DIR/secrets.auto.tfvars" && -z "${TF_VAR_alert_email:-}" ]]; then
  echo "Missing alert email. Create infra/terraform/secrets.auto.tfvars containing: alert_email = \"you@example.com\""
  exit 1
fi

cd "$TF_DIR"
mkdir -p build
terraform init -input=false
terraform plan -input=false -out=build/tfplan

if [[ "${1:-}" != "--auto-approve" ]]; then
  read -r -p "Apply this plan? Type 'yes' to continue: " answer
  [[ "$answer" == "yes" ]] || { echo "Cancelled. Nothing was changed."; exit 0; }
fi

terraform apply -input=false build/tfplan
echo
echo "Deploy complete. Outputs:"
terraform output
echo
echo "First deploy? Confirm the two 'AWS Notification - Subscription Confirmation' emails (leak alerts and billing)."
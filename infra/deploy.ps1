<#
One-command deploy for the canary gateway (issue #5).
Usage, from the repo root:   .\infra\deploy.ps1
Skip the confirmation:       .\infra\deploy.ps1 -AutoApprove
#>
param([switch]$AutoApprove)

$ErrorActionPreference = "Stop"
$tfDir = Join-Path $PSScriptRoot "terraform"

# 1. Required tools
foreach ($cmd in @("terraform", "aws")) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        throw "'$cmd' is not installed or not on PATH."
    }
}

# 2. AWS login
Write-Host "Checking AWS login..."
$account = aws sts get-caller-identity --query Account --output text
if ($LASTEXITCODE -ne 0) { throw "AWS CLI is not logged in. Run 'aws configure' first." }
Write-Host "Deploying to AWS account $account"

# 3. Alert email (kept out of git)
$secrets = Join-Path $tfDir "secrets.auto.tfvars"
if (-not (Test-Path $secrets) -and -not $env:TF_VAR_alert_email) {
    throw "Missing alert email. Create infra/terraform/secrets.auto.tfvars containing: alert_email = `"you@example.com`""
}

Push-Location $tfDir
try {
    New-Item -ItemType Directory -Force -Path "build" | Out-Null

    # 4. Init, plan, apply
    terraform init -input=false
    if ($LASTEXITCODE -ne 0) { throw "terraform init failed" }

    terraform plan -input=false -out="build/tfplan"
    if ($LASTEXITCODE -ne 0) { throw "terraform plan failed" }

    if (-not $AutoApprove) {
        $answer = Read-Host "Apply this plan? Type 'yes' to continue"
        if ($answer -ne "yes") { Write-Host "Cancelled. Nothing was changed."; return }
    }

    terraform apply -input=false "build/tfplan"
    if ($LASTEXITCODE -ne 0) { throw "terraform apply failed" }

    # 5. Show the URLs
    Write-Host ""
    Write-Host "Deploy complete. Outputs:"
    terraform output
    Write-Host ""
    Write-Host "First deploy? Confirm the two 'AWS Notification - Subscription Confirmation' emails (leak alerts and billing)."
}
finally {
    Pop-Location
}
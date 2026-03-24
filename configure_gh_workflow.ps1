<#
.SYNOPSIS
    Generate a self-contained GitHub Actions package for Sentinel extraction and restoration.

.DESCRIPTION
    This script generates the gh/ output directory containing:
      - code/sentinel_extractor.py, code/sentinel_restore.py, code/requirements.txt
      - .github/workflows/sentinel-extract.yml (daily scheduled + manual)
      - .github/workflows/sentinel-restore.yml (optional schedule + manual dispatch)
      - .gitignore

    Workspace configuration is injected into the workflow YAML files.
    Credentials (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET) must be
    stored as secrets in a GitHub Environment.

.PARAMETER EnvName
    Name of the GitHub Environment (default: sentinel-prod).

.EXAMPLE
    ./configure_gh_workflow.ps1
    ./configure_gh_workflow.ps1 -EnvName "sentinel-staging"
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$EnvName = ""
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Read-ValueOrDefault {
    param(
        [string]$Prompt,
        [string]$Default = ""
    )
    $input_val = Read-Host "$Prompt [$Default]"
    if ([string]::IsNullOrWhiteSpace($input_val)) { return $Default }
    return $input_val
}

# ---------------------------------------------------------------------------
# Locate repo root
# ---------------------------------------------------------------------------
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$repoRoot = $scriptDir
if (-not (Test-Path (Join-Path $repoRoot "code"))) {
    $repoRoot = Split-Path -Parent $scriptDir
}

$codeDir = Join-Path $repoRoot "code"
if (-not (Test-Path $codeDir)) { throw "code/ directory not found at $codeDir" }
if (-not (Test-Path (Join-Path $codeDir "sentinel_extractor.py"))) { throw "sentinel_extractor.py not found in $codeDir" }
if (-not (Test-Path (Join-Path $codeDir "sentinel_restore.py")))   { throw "sentinel_restore.py not found in $codeDir" }
if (-not (Test-Path (Join-Path $codeDir "requirements.txt")))      { throw "requirements.txt not found in $codeDir" }

# ---------------------------------------------------------------------------
# GitHub Environment name
# ---------------------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($EnvName)) {
    $EnvName = Read-ValueOrDefault "GitHub Environment name" "sentinel-prod"
}

# ---------------------------------------------------------------------------
# 1. Collect source workspace configuration
# ---------------------------------------------------------------------------
Write-Step "Sentinel Extractor — GitHub Actions Configuration"
Write-Host "This script generates a self-contained GitHub Actions package in the gh/ directory."
Write-Host "The package includes workflow files and a copy of the extraction/restore scripts."
Write-Host ""

Write-Step "Source Sentinel Workspace Configuration"
$SentinelSubId   = Read-Host "Sentinel source subscription ID"
$SentinelRG      = Read-Host "Sentinel source resource group"
$SentinelWS      = Read-Host "Log Analytics workspace name"

Write-Step "Optional Source Resource Groups (press Enter to skip)"
$LogicAppsRG  = Read-ValueOrDefault "Logic Apps resource group"
$DcrRG        = Read-ValueOrDefault "DCR resource group"
$DceRG        = Read-ValueOrDefault "DCE resource group"
$WorkbooksRG  = Read-ValueOrDefault "Workbooks resource group" $SentinelRG

# ---------------------------------------------------------------------------
# 2. Collect restore target configuration
# ---------------------------------------------------------------------------
Write-Step "Restore Target Configuration"
Write-Host "Configure default restore target workspace."
Write-Host "These values can be overridden at workflow dispatch time."
Write-Host ""

$TargetSubId       = Read-ValueOrDefault "Target subscription ID" $SentinelSubId
$TargetRG          = Read-ValueOrDefault "Target resource group" $SentinelRG
$TargetWS          = Read-ValueOrDefault "Target workspace name" $SentinelWS

Write-Step "Optional Target Resource Groups (press Enter to skip)"
$TargetLogicAppsRG = Read-ValueOrDefault "Target Logic Apps resource group"
$TargetDcrRG       = Read-ValueOrDefault "Target DCR resource group"
$TargetDceRG       = Read-ValueOrDefault "Target DCE resource group"
$TargetWorkbooksRG = Read-ValueOrDefault "Target Workbooks resource group" $TargetRG
$TargetLocation    = Read-ValueOrDefault "Target Azure region (e.g. westeurope)"

# ---------------------------------------------------------------------------
# 3. Collect schedule configuration
# ---------------------------------------------------------------------------
Write-Step "Extraction Schedule"
Write-Host "Enter a cron expression for the daily extraction (5-field, UTC)."
Write-Host "Examples: '0 2 * * *' = daily at 2:00 AM, '0 */6 * * *' = every 6 hours"
$ExtractSchedule = Read-ValueOrDefault "Extraction schedule" "0 2 * * *"

Write-Step "Restore Schedule (optional)"
Write-Host "Enter a cron expression for scheduled restores, or press Enter to skip."
Write-Host "Leave empty for manual-only restore (workflow_dispatch)."
$RestoreSchedule = Read-ValueOrDefault "Restore schedule (empty = manual only)"

# ---------------------------------------------------------------------------
# 4. Generate gh/ directory structure
# ---------------------------------------------------------------------------
Write-Step "Generating gh/ directory..."

$ghDir = Join-Path $repoRoot "gh"

if (Test-Path $ghDir) {
    Write-Host "Existing gh/ directory found — removing and regenerating." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $ghDir
}

New-Item -ItemType Directory -Path (Join-Path $ghDir "code") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $ghDir ".github/workflows") -Force | Out-Null

# Copy code files
Copy-Item (Join-Path $codeDir "sentinel_extractor.py") (Join-Path $ghDir "code/sentinel_extractor.py")
Copy-Item (Join-Path $codeDir "sentinel_restore.py")   (Join-Path $ghDir "code/sentinel_restore.py")
Copy-Item (Join-Path $codeDir "requirements.txt")      (Join-Path $ghDir "code/requirements.txt")

Write-Host "Copied code/ scripts into gh/code/." -ForegroundColor Green

# ---------------------------------------------------------------------------
# 5. Generate .gitignore
# ---------------------------------------------------------------------------
$gitignoreContent = @"
# Environment / secrets
.env
*.env

# Python
__pycache__/
*.pyc
*.pyo
*.egg-info/
dist/
build/
"@
Set-Content -Path (Join-Path $ghDir ".gitignore") -Value $gitignoreContent -Encoding UTF8
Write-Host "Generated gh/.gitignore" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 6. Generate extraction workflow
# ---------------------------------------------------------------------------
$timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm UTC")

$extractWorkflow = @"
# ---------------------------------------------------------
# Sentinel Configuration Extract — GitHub Actions Workflow
# Generated by configure_gh_workflow.ps1 on $timestamp
# ---------------------------------------------------------
name: Sentinel Configuration Extract

on:
  schedule:
    - cron: '$ExtractSchedule'
  workflow_dispatch: {}

permissions:
  contents: write

env:
  AZURE_SUBSCRIPTION_ID: '$SentinelSubId'
  AZURE_RESOURCE_GROUP: '$SentinelRG'
  AZURE_WORKSPACE_NAME: '$SentinelWS'
  AZURE_LOGIC_APPS_RESOURCE_GROUP: '$LogicAppsRG'
  AZURE_DCR_RESOURCE_GROUP: '$DcrRG'
  AZURE_DCE_RESOURCE_GROUP: '$DceRG'
  AZURE_WORKBOOKS_RESOURCE_GROUP: '$WorkbooksRG'

jobs:
  extract:
    runs-on: ubuntu-latest
    environment: $EnvName
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: pip
          cache-dependency-path: code/requirements.txt

      - name: Install dependencies
        run: pip install -r code/requirements.txt

      - name: Run Sentinel Extractor
        env:
          AZURE_TENANT_ID: `${{ secrets.AZURE_TENANT_ID }}
          AZURE_CLIENT_ID: `${{ secrets.AZURE_CLIENT_ID }}
          AZURE_CLIENT_SECRET: `${{ secrets.AZURE_CLIENT_SECRET }}
        run: python code/sentinel_extractor.py --output-dir output

      - name: Commit and push changes
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add output/
          if git diff --staged --quiet; then
            echo "No changes detected — nothing to commit."
          else
            git commit -m "Sentinel backup `$(date -u +'%Y-%m-%d %H:%M UTC')"
            git push
          fi
"@

Set-Content -Path (Join-Path $ghDir ".github/workflows/sentinel-extract.yml") -Value $extractWorkflow -Encoding UTF8
Write-Host "Generated gh/.github/workflows/sentinel-extract.yml" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 7. Generate restore workflow
# ---------------------------------------------------------------------------
$restoreScheduleBlock = ""
if (-not [string]::IsNullOrWhiteSpace($RestoreSchedule)) {
    $restoreScheduleBlock = @"
  schedule:
    - cron: '$RestoreSchedule'
"@
}

$restoreWorkflow = @"
# ---------------------------------------------------------
# Sentinel Configuration Restore — GitHub Actions Workflow
# Generated by configure_gh_workflow.ps1 on $timestamp
# ---------------------------------------------------------
name: Sentinel Configuration Restore

on:
$restoreScheduleBlock
  workflow_dispatch:
    inputs:
      target_subscription_id:
        description: 'Target subscription ID (leave empty for default)'
        required: false
        default: ''
      target_resource_group:
        description: 'Target resource group (leave empty for default)'
        required: false
        default: ''
      target_workspace_name:
        description: 'Target workspace name (leave empty for default)'
        required: false
        default: ''
      restore_flags:
        description: 'Restore flags (e.g. --restore-all or --restore-alert-rules --restore-hunting)'
        required: false
        default: '--restore-all'
      generate_new_id:
        description: 'Generate new IDs for rules (avoids soft-delete 409 conflicts)'
        type: boolean
        required: false
        default: false
      logic_app_mode:
        description: 'Logic App restore mode'
        type: choice
        required: false
        options:
          - same-tenant
          - new-environment
        default: same-tenant

permissions:
  contents: read

env:
  # Source workspace (used to locate backup directory)
  AZURE_SUBSCRIPTION_ID: '$SentinelSubId'
  AZURE_WORKSPACE_NAME: '$SentinelWS'
  # Default restore target
  AZURE_TARGET_SUBSCRIPTION_ID: '$TargetSubId'
  AZURE_TARGET_RESOURCE_GROUP: '$TargetRG'
  AZURE_TARGET_WORKSPACE_NAME: '$TargetWS'
  AZURE_TARGET_LOGIC_APPS_RESOURCE_GROUP: '$TargetLogicAppsRG'
  AZURE_TARGET_DCR_RESOURCE_GROUP: '$TargetDcrRG'
  AZURE_TARGET_DCE_RESOURCE_GROUP: '$TargetDceRG'
  AZURE_TARGET_WORKBOOKS_RESOURCE_GROUP: '$TargetWorkbooksRG'
  AZURE_TARGET_LOCATION: '$TargetLocation'

jobs:
  restore:
    runs-on: ubuntu-latest
    environment: $EnvName
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: pip
          cache-dependency-path: code/requirements.txt

      - name: Install dependencies
        run: pip install -r code/requirements.txt

      - name: Validate restore flags
        id: validate
        env:
          RAW_FLAGS: `${{ github.event.inputs.restore_flags || '--restore-all' }}
        run: |
          # Allow only known flags (reject unexpected characters)
          if ! echo "`$RAW_FLAGS" | grep -qE '^(--[a-z][-a-z]*( +|`$))+`$'; then
            echo "::error::Invalid restore flags: `$RAW_FLAGS"
            exit 1
          fi
          echo "flags=`$RAW_FLAGS" >> `$GITHUB_OUTPUT

      - name: Resolve target parameters
        id: params
        run: |
          echo "sub=`${INPUT_SUB:-`$AZURE_TARGET_SUBSCRIPTION_ID}" >> `$GITHUB_OUTPUT
          echo "rg=`${INPUT_RG:-`$AZURE_TARGET_RESOURCE_GROUP}" >> `$GITHUB_OUTPUT
          echo "ws=`${INPUT_WS:-`$AZURE_TARGET_WORKSPACE_NAME}" >> `$GITHUB_OUTPUT
        env:
          INPUT_SUB: `${{ github.event.inputs.target_subscription_id }}
          INPUT_RG: `${{ github.event.inputs.target_resource_group }}
          INPUT_WS: `${{ github.event.inputs.target_workspace_name }}

      - name: Run Sentinel Restore
        env:
          AZURE_TENANT_ID: `${{ secrets.AZURE_TENANT_ID }}
          AZURE_CLIENT_ID: `${{ secrets.AZURE_CLIENT_ID }}
          AZURE_CLIENT_SECRET: `${{ secrets.AZURE_CLIENT_SECRET }}
          AZURE_TARGET_SUBSCRIPTION_ID: `${{ steps.params.outputs.sub }}
          AZURE_TARGET_RESOURCE_GROUP: `${{ steps.params.outputs.rg }}
          AZURE_TARGET_WORKSPACE_NAME: `${{ steps.params.outputs.ws }}
          AZURE_BACKUP_SOURCE_DIR: output/`${{ env.AZURE_SUBSCRIPTION_ID }}/`${{ env.AZURE_WORKSPACE_NAME }}
          RESTORE_FLAGS: `${{ steps.validate.outputs.flags }}
          GENERATE_NEW_ID: `${{ github.event.inputs.generate_new_id }}
          LOGIC_APP_MODE: `${{ github.event.inputs.logic_app_mode }}
        run: |
          FLAGS="`$RESTORE_FLAGS"
          if [ "`$GENERATE_NEW_ID" = "true" ]; then
            FLAGS="`$FLAGS --generate-new-id"
          fi
          FLAGS="`$FLAGS --logic-app-mode `${LOGIC_APP_MODE:-same-tenant}"
          python code/sentinel_restore.py `$FLAGS
"@

Set-Content -Path (Join-Path $ghDir ".github/workflows/sentinel-restore.yml") -Value $restoreWorkflow -Encoding UTF8
Write-Host "Generated gh/.github/workflows/sentinel-restore.yml" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 8. Summary and next steps
# ---------------------------------------------------------------------------
Write-Step "GitHub Actions package generated successfully!"
Write-Host ""
Write-Host "Output directory: $ghDir"
Write-Host ""

Write-Host "Contents:" -ForegroundColor White
Get-ChildItem -Path $ghDir -Recurse -File | ForEach-Object {
    $rel = $_.FullName.Substring($ghDir.Length + 1)
    Write-Host "  $rel"
}

Write-Host ""
Write-Host "=== Next Steps ===" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. Copy the contents of gh/ to the root of your target GitHub repository:"
Write-Host "     Copy-Item -Recurse gh/.github <your-repo>/"
Write-Host "     Copy-Item -Recurse gh/code    <your-repo>/"
Write-Host "     Copy-Item gh/.gitignore <your-repo>/"
Write-Host ""
Write-Host "2. Create a GitHub Environment named '$EnvName' in your repository:"
Write-Host "     Repository Settings > Environments > New environment > '$EnvName'"
Write-Host ""
Write-Host "3. Add the following secrets to the '$EnvName' environment:"
Write-Host "     - AZURE_TENANT_ID     — Azure AD tenant ID"
Write-Host "     - AZURE_CLIENT_ID     — App Registration client ID"
Write-Host "     - AZURE_CLIENT_SECRET — App Registration client secret"
Write-Host ""
Write-Host "4. Ensure the App Registration has the required RBAC roles:"
Write-Host "     - Reader on the Sentinel resource group"
Write-Host "     - Microsoft Sentinel Reader (for extraction)"
Write-Host "     - Microsoft Sentinel Contributor (for restoration)"
Write-Host ""
Write-Host "5. Push the changes and enable the workflows in GitHub Actions."

# ---------------------------------------------------------------------------
# 9. Optional: configure via gh CLI
# ---------------------------------------------------------------------------
$ghCli = Get-Command gh -ErrorAction SilentlyContinue
if ($ghCli) {
    Write-Host ""
    Write-Step "GitHub CLI detected"
    $configureGh = Read-ValueOrDefault "Configure GitHub Environment and secrets now via 'gh' CLI? (y/n)" "n"

    if ($configureGh -ieq "y") {
        # Detect repo
        $ghRepo = ""
        try {
            $remoteUrl = git remote get-url origin 2>$null
            if ($remoteUrl -match 'github\.com[:/]([^/]+/[^/.]+?)(\.git)?$') {
                $ghRepo = $Matches[1]
            }
        } catch {}

        if ([string]::IsNullOrWhiteSpace($ghRepo)) {
            $ghRepo = Read-Host "GitHub repository (owner/repo)"
        } else {
            $ghRepo = Read-ValueOrDefault "GitHub repository" $ghRepo
        }

        Write-Step "Creating GitHub Environment '$EnvName'..."
        try {
            gh api --method PUT "repos/$ghRepo/environments/$EnvName" --silent 2>$null
        } catch {
            Write-Host "Could not create environment (may already exist or require admin access)." -ForegroundColor Yellow
        }

        Write-Step "Setting environment secrets..."
        Write-Host "Enter the values for each secret. Input will be masked."
        Write-Host ""

        $tenantIdVal = Read-Host "AZURE_TENANT_ID" -MaskInput
        if (-not [string]::IsNullOrWhiteSpace($tenantIdVal)) {
            $tenantIdVal | gh secret set AZURE_TENANT_ID --repo $ghRepo --env $EnvName
            Write-Host "  AZURE_TENANT_ID set." -ForegroundColor Green
        }

        $clientIdVal = Read-Host "AZURE_CLIENT_ID" -MaskInput
        if (-not [string]::IsNullOrWhiteSpace($clientIdVal)) {
            $clientIdVal | gh secret set AZURE_CLIENT_ID --repo $ghRepo --env $EnvName
            Write-Host "  AZURE_CLIENT_ID set." -ForegroundColor Green
        }

        $clientSecretVal = Read-Host "AZURE_CLIENT_SECRET" -MaskInput
        if (-not [string]::IsNullOrWhiteSpace($clientSecretVal)) {
            $clientSecretVal | gh secret set AZURE_CLIENT_SECRET --repo $ghRepo --env $EnvName
            Write-Host "  AZURE_CLIENT_SECRET set." -ForegroundColor Green
        }

        Write-Host ""
        Write-Host "GitHub Environment '$EnvName' configured." -ForegroundColor Green
    }
}

Write-Step "Done!"

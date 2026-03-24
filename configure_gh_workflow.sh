#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# configure_gh_workflow.sh
#
# Generate a self-contained GitHub Actions package for automated Sentinel
# configuration extraction (daily) and restoration (manual / scheduled).
#
# This script:
#   1. Prompts for Sentinel workspace details and optional resource groups.
#   2. Prompts for restore target workspace details (optional).
#   3. Prompts for extraction and restore schedules (cron).
#   4. Generates the gh/ output directory with:
#        - code/sentinel_extractor.py, code/sentinel_restore.py, code/requirements.txt
#        - .github/workflows/sentinel-extract.yml
#        - .github/workflows/sentinel-restore.yml
#        - .gitignore
#   5. Optionally configures the GitHub Environment and secrets via the gh CLI.
#
# Usage:
#   ./configure_gh_workflow.sh [--env-name <name>]
# ---------------------------------------------------------------------------

set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
cyan="\033[36m"
green="\033[32m"
yellow="\033[33m"
red="\033[31m"
reset="\033[0m"

step() {
    echo ""
    echo -e "${cyan}==> $1${reset}"
}

error_exit() {
    echo -e "${red}ERROR: $1${reset}" >&2
    exit 1
}

read_value() {
    local prompt="$1"
    local default="${2:-}"
    local value
    if [ -n "$default" ]; then
        read -rp "$prompt [$default]: " value
        echo "${value:-$default}"
    else
        read -rp "$prompt: " value
        echo "$value"
    fi
}

read_secret() {
    local prompt="$1"
    local value
    read -srp "$prompt: " value
    printf '\n' >&2
    echo "$value"
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
ENV_NAME=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --env-name)      ENV_NAME="$2";  shift 2;;
        -h|--help)
            echo "Usage: $0 [--env-name <github-environment-name>]"
            exit 0;;
        *) error_exit "Unknown argument: $1";;
    esac
done

[ -z "$ENV_NAME" ] && ENV_NAME=$(read_value "GitHub Environment name" "sentinel-prod")

# ---------------------------------------------------------------------------
# Locate repo root
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"
if [ ! -d "$REPO_ROOT/code" ]; then
    REPO_ROOT="$(dirname "$SCRIPT_DIR")"
fi
CODE_DIR="$REPO_ROOT/code"
[ -d "$CODE_DIR" ] || error_exit "code/ directory not found at $CODE_DIR"
[ -f "$CODE_DIR/sentinel_extractor.py" ] || error_exit "sentinel_extractor.py not found in $CODE_DIR"
[ -f "$CODE_DIR/sentinel_restore.py" ]   || error_exit "sentinel_restore.py not found in $CODE_DIR"
[ -f "$CODE_DIR/requirements.txt" ]      || error_exit "requirements.txt not found in $CODE_DIR"

# ---------------------------------------------------------------------------
# 1. Collect source workspace configuration
# ---------------------------------------------------------------------------
step "Sentinel Extractor — GitHub Actions Configuration"
echo "This script generates a self-contained GitHub Actions package in the gh/ directory."
echo "The package includes workflow files and a copy of the extraction/restore scripts."
echo ""

step "Source Sentinel Workspace Configuration"
SENTINEL_SUB_ID=$(read_value "Sentinel source subscription ID")
SENTINEL_RG=$(read_value "Sentinel source resource group")
SENTINEL_WS=$(read_value "Log Analytics workspace name")

step "Optional Source Resource Groups (press Enter to skip)"
LOGIC_APPS_RG=$(read_value "Logic Apps resource group" "")
DCR_RG=$(read_value "DCR resource group" "")
DCE_RG=$(read_value "DCE resource group" "")
WORKBOOKS_RG=$(read_value "Workbooks resource group" "$SENTINEL_RG")

# ---------------------------------------------------------------------------
# 2. Collect restore target configuration
# ---------------------------------------------------------------------------
step "Restore Target Configuration"
echo "Configure default restore target workspace."
echo "These values can be overridden at workflow dispatch time."
echo ""

TARGET_SUB_ID=$(read_value "Target subscription ID" "$SENTINEL_SUB_ID")
TARGET_RG=$(read_value "Target resource group" "$SENTINEL_RG")
TARGET_WS=$(read_value "Target workspace name" "$SENTINEL_WS")

step "Optional Target Resource Groups (press Enter to skip)"
TARGET_LOGIC_APPS_RG=$(read_value "Target Logic Apps resource group" "")
TARGET_DCR_RG=$(read_value "Target DCR resource group" "")
TARGET_DCE_RG=$(read_value "Target DCE resource group" "")
TARGET_WORKBOOKS_RG=$(read_value "Target Workbooks resource group" "$TARGET_RG")
TARGET_LOCATION=$(read_value "Target Azure region (e.g. westeurope)" "")

# ---------------------------------------------------------------------------
# 3. Collect schedule configuration
# ---------------------------------------------------------------------------
step "Extraction Schedule"
echo "Enter a cron expression for the daily extraction (5-field, UTC)."
echo "Examples: '0 2 * * *' = daily at 2:00 AM, '0 */6 * * *' = every 6 hours"
EXTRACT_SCHEDULE=$(read_value "Extraction schedule" "0 2 * * *")

step "Restore Schedule (optional)"
echo "Enter a cron expression for scheduled restores, or press Enter to skip."
echo "Leave empty for manual-only restore (workflow_dispatch)."
RESTORE_SCHEDULE=$(read_value "Restore schedule (empty = manual only)" "")

# ---------------------------------------------------------------------------
# 4. Generate gh/ directory structure
# ---------------------------------------------------------------------------
step "Generating gh/ directory..."

GH_DIR="$REPO_ROOT/gh"

# Clean previous output
if [ -d "$GH_DIR" ]; then
    echo -e "${yellow}Existing gh/ directory found — removing and regenerating.${reset}"
    rm -rf "$GH_DIR"
fi

mkdir -p "$GH_DIR/code"
mkdir -p "$GH_DIR/.github/workflows"

# Copy code files
cp "$CODE_DIR/sentinel_extractor.py" "$GH_DIR/code/sentinel_extractor.py"
cp "$CODE_DIR/sentinel_restore.py"   "$GH_DIR/code/sentinel_restore.py"
cp "$CODE_DIR/requirements.txt"      "$GH_DIR/code/requirements.txt"

echo -e "${green}Copied code/ scripts into gh/code/.${reset}"

# ---------------------------------------------------------------------------
# 5. Generate .gitignore
# ---------------------------------------------------------------------------
cat > "$GH_DIR/.gitignore" << 'GITIGNORE_EOF'
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
GITIGNORE_EOF

echo -e "${green}Generated gh/.gitignore${reset}"

# ---------------------------------------------------------------------------
# 6. Generate extraction workflow
# ---------------------------------------------------------------------------
cat > "$GH_DIR/.github/workflows/sentinel-extract.yml" << EXTRACT_EOF
# ---------------------------------------------------------
# Sentinel Configuration Extract — GitHub Actions Workflow
# Generated by configure_gh_workflow.sh on $(date -u +"%Y-%m-%d %H:%M UTC")
# ---------------------------------------------------------
name: Sentinel Configuration Extract

on:
  schedule:
    - cron: '${EXTRACT_SCHEDULE}'
  workflow_dispatch: {}

permissions:
  contents: write

env:
  AZURE_SUBSCRIPTION_ID: '${SENTINEL_SUB_ID}'
  AZURE_RESOURCE_GROUP: '${SENTINEL_RG}'
  AZURE_WORKSPACE_NAME: '${SENTINEL_WS}'
  AZURE_LOGIC_APPS_RESOURCE_GROUP: '${LOGIC_APPS_RG}'
  AZURE_DCR_RESOURCE_GROUP: '${DCR_RG}'
  AZURE_DCE_RESOURCE_GROUP: '${DCE_RG}'
  AZURE_WORKBOOKS_RESOURCE_GROUP: '${WORKBOOKS_RG}'

jobs:
  extract:
    runs-on: ubuntu-latest
    environment: ${ENV_NAME}
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
          AZURE_TENANT_ID: \${{ secrets.AZURE_TENANT_ID }}
          AZURE_CLIENT_ID: \${{ secrets.AZURE_CLIENT_ID }}
          AZURE_CLIENT_SECRET: \${{ secrets.AZURE_CLIENT_SECRET }}
        run: python code/sentinel_extractor.py --output-dir output

      - name: Commit and push changes
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add output/
          if git diff --staged --quiet; then
            echo "No changes detected — nothing to commit."
          else
            git commit -m "Sentinel backup \$(date -u +'%Y-%m-%d %H:%M UTC')"
            git push
          fi
EXTRACT_EOF

echo -e "${green}Generated gh/.github/workflows/sentinel-extract.yml${reset}"

# ---------------------------------------------------------------------------
# 7. Generate restore workflow
# ---------------------------------------------------------------------------

# Build the schedule trigger section
RESTORE_SCHEDULE_BLOCK=""
if [ -n "$RESTORE_SCHEDULE" ]; then
    RESTORE_SCHEDULE_BLOCK="  schedule:
    - cron: '${RESTORE_SCHEDULE}'"
fi

cat > "$GH_DIR/.github/workflows/sentinel-restore.yml" << RESTORE_EOF
# ---------------------------------------------------------
# Sentinel Configuration Restore — GitHub Actions Workflow
# Generated by configure_gh_workflow.sh on $(date -u +"%Y-%m-%d %H:%M UTC")
# ---------------------------------------------------------
name: Sentinel Configuration Restore

on:
${RESTORE_SCHEDULE_BLOCK}
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
  AZURE_SUBSCRIPTION_ID: '${SENTINEL_SUB_ID}'
  AZURE_WORKSPACE_NAME: '${SENTINEL_WS}'
  # Default restore target
  AZURE_TARGET_SUBSCRIPTION_ID: '${TARGET_SUB_ID}'
  AZURE_TARGET_RESOURCE_GROUP: '${TARGET_RG}'
  AZURE_TARGET_WORKSPACE_NAME: '${TARGET_WS}'
  AZURE_TARGET_LOGIC_APPS_RESOURCE_GROUP: '${TARGET_LOGIC_APPS_RG}'
  AZURE_TARGET_DCR_RESOURCE_GROUP: '${TARGET_DCR_RG}'
  AZURE_TARGET_DCE_RESOURCE_GROUP: '${TARGET_DCE_RG}'
  AZURE_TARGET_WORKBOOKS_RESOURCE_GROUP: '${TARGET_WORKBOOKS_RG}'
  AZURE_TARGET_LOCATION: '${TARGET_LOCATION}'

jobs:
  restore:
    runs-on: ubuntu-latest
    environment: ${ENV_NAME}
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
          RAW_FLAGS: \${{ github.event.inputs.restore_flags || '--restore-all' }}
        run: |
          # Allow only known flags (reject unexpected characters)
          if ! echo "\$RAW_FLAGS" | grep -qE '^(--[a-z][-a-z]*( +|\$))+\$'; then
            echo "::error::Invalid restore flags: \$RAW_FLAGS"
            exit 1
          fi
          echo "flags=\$RAW_FLAGS" >> \$GITHUB_OUTPUT

      - name: Resolve target parameters
        id: params
        run: |
          echo "sub=\${INPUT_SUB:-\$AZURE_TARGET_SUBSCRIPTION_ID}" >> \$GITHUB_OUTPUT
          echo "rg=\${INPUT_RG:-\$AZURE_TARGET_RESOURCE_GROUP}" >> \$GITHUB_OUTPUT
          echo "ws=\${INPUT_WS:-\$AZURE_TARGET_WORKSPACE_NAME}" >> \$GITHUB_OUTPUT
        env:
          INPUT_SUB: \${{ github.event.inputs.target_subscription_id }}
          INPUT_RG: \${{ github.event.inputs.target_resource_group }}
          INPUT_WS: \${{ github.event.inputs.target_workspace_name }}

      - name: Run Sentinel Restore
        env:
          AZURE_TENANT_ID: \${{ secrets.AZURE_TENANT_ID }}
          AZURE_CLIENT_ID: \${{ secrets.AZURE_CLIENT_ID }}
          AZURE_CLIENT_SECRET: \${{ secrets.AZURE_CLIENT_SECRET }}
          AZURE_TARGET_SUBSCRIPTION_ID: \${{ steps.params.outputs.sub }}
          AZURE_TARGET_RESOURCE_GROUP: \${{ steps.params.outputs.rg }}
          AZURE_TARGET_WORKSPACE_NAME: \${{ steps.params.outputs.ws }}
          AZURE_BACKUP_SOURCE_DIR: output/\${{ env.AZURE_SUBSCRIPTION_ID }}/\${{ env.AZURE_WORKSPACE_NAME }}
          RESTORE_FLAGS: \${{ steps.validate.outputs.flags }}
          GENERATE_NEW_ID: \${{ github.event.inputs.generate_new_id }}
          LOGIC_APP_MODE: \${{ github.event.inputs.logic_app_mode }}
        run: |
          FLAGS="\$RESTORE_FLAGS"
          if [ "\$GENERATE_NEW_ID" = "true" ]; then
            FLAGS="\$FLAGS --generate-new-id"
          fi
          FLAGS="\$FLAGS --logic-app-mode \${LOGIC_APP_MODE:-same-tenant}"
          python code/sentinel_restore.py \$FLAGS
RESTORE_EOF

echo -e "${green}Generated gh/.github/workflows/sentinel-restore.yml${reset}"

# ---------------------------------------------------------------------------
# 8. Summary and next steps
# ---------------------------------------------------------------------------
step "GitHub Actions package generated successfully!"
echo ""
echo "Output directory: $GH_DIR"
echo ""
echo "Contents:"
find "$GH_DIR" -type f | sort | while read -r f; do
    echo "  ${f#$GH_DIR/}"
done

echo ""
echo -e "${yellow}=== Next Steps ===${reset}"
echo ""
echo "1. Copy the contents of gh/ to the root of your target GitHub repository:"
echo "     cp -r gh/.github <your-repo>/"
echo "     cp -r gh/code    <your-repo>/"
echo "     cp gh/.gitignore <your-repo>/"
echo ""
echo "2. Create a GitHub Environment named '${ENV_NAME}' in your repository:"
echo "     Repository Settings > Environments > New environment > '${ENV_NAME}'"
echo ""
echo "3. Add the following secrets to the '${ENV_NAME}' environment:"
echo "     • AZURE_TENANT_ID     — Azure AD tenant ID"
echo "     • AZURE_CLIENT_ID     — App Registration client ID"
echo "     • AZURE_CLIENT_SECRET — App Registration client secret"
echo ""
echo "4. Ensure the App Registration has the required RBAC roles:"
echo "     • Reader on the Sentinel resource group"
echo "     • Microsoft Sentinel Reader (for extraction)"
echo "     • Microsoft Sentinel Contributor (for restoration)"
echo ""
echo "5. Push the changes and enable the workflows in GitHub Actions."

# ---------------------------------------------------------------------------
# 9. Optional: configure via gh CLI
# ---------------------------------------------------------------------------
if command -v gh &>/dev/null; then
    echo ""
    step "GitHub CLI detected"
    CONFIGURE_GH=$(read_value "Configure GitHub Environment and secrets now via 'gh' CLI? (y/n)" "n")

    if [ "$CONFIGURE_GH" = "y" ] || [ "$CONFIGURE_GH" = "Y" ]; then
        # Detect repo from git remote or prompt
        GH_REPO=""
        if git remote get-url origin &>/dev/null; then
            REMOTE_URL=$(git remote get-url origin)
            # Extract owner/repo from HTTPS or SSH URL
            GH_REPO=$(echo "$REMOTE_URL" | sed -E 's|.*github\.com[:/]([^/]+/[^/.]+)(\.git)?$|\1|')
        fi
        if [ -z "$GH_REPO" ]; then
            GH_REPO=$(read_value "GitHub repository (owner/repo)")
        else
            GH_REPO=$(read_value "GitHub repository" "$GH_REPO")
        fi

        step "Creating GitHub Environment '${ENV_NAME}'..."
        gh api --method PUT "repos/${GH_REPO}/environments/${ENV_NAME}" \
            --silent 2>/dev/null || echo -e "${yellow}Could not create environment (may already exist or require admin access).${reset}"

        step "Setting environment secrets..."
        echo "Enter the values for each secret. Input will be hidden."
        echo ""

        TENANT_ID_VAL=$(read_secret "AZURE_TENANT_ID")
        if [ -n "$TENANT_ID_VAL" ]; then
            echo "$TENANT_ID_VAL" | gh secret set AZURE_TENANT_ID --repo "$GH_REPO" --env "$ENV_NAME"
            echo -e "  ${green}AZURE_TENANT_ID set.${reset}"
        fi

        CLIENT_ID_VAL=$(read_secret "AZURE_CLIENT_ID")
        if [ -n "$CLIENT_ID_VAL" ]; then
            echo "$CLIENT_ID_VAL" | gh secret set AZURE_CLIENT_ID --repo "$GH_REPO" --env "$ENV_NAME"
            echo -e "  ${green}AZURE_CLIENT_ID set.${reset}"
        fi

        CLIENT_SECRET_VAL=$(read_secret "AZURE_CLIENT_SECRET")
        if [ -n "$CLIENT_SECRET_VAL" ]; then
            echo "$CLIENT_SECRET_VAL" | gh secret set AZURE_CLIENT_SECRET --repo "$GH_REPO" --env "$ENV_NAME"
            echo -e "  ${green}AZURE_CLIENT_SECRET set.${reset}"
        fi

        echo ""
        echo -e "${green}GitHub Environment '${ENV_NAME}' configured.${reset}"
    fi
fi

step "Done!"

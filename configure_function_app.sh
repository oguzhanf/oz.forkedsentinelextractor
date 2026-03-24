#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# configure_function_app.sh
#
# Configure and package the Sentinel Extractor Function App for deployment.
#
# This script:
#   1. Configures the Function App application settings (Sentinel workspace,
#      DCE/DCR/Workbook/Logic Apps resource groups, export target, schedule).
#   2. Assigns the Managed Identity the required RBAC roles on the source workspace.
#   3. Generates a deployment ZIP package from function_app/ + code/ that can be
#      imported via the Azure Portal or az functionapp deployment source config-zip.
#
# The Function App must already be deployed with a system-assigned Managed Identity.
#
# Usage:
#   ./configure_function_app.sh \
#       --subscription-id <sub-id> \
#       --resource-group <rg> \
#       --function-app-name <name>
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
SUBSCRIPTION_ID=""
RESOURCE_GROUP=""
FUNCTION_APP_NAME=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --subscription-id)  SUBSCRIPTION_ID="$2";  shift 2;;
        --resource-group)   RESOURCE_GROUP="$2";    shift 2;;
        --function-app-name) FUNCTION_APP_NAME="$2"; shift 2;;
        -h|--help)
            echo "Usage: $0 --subscription-id <id> --resource-group <rg> --function-app-name <name>"
            exit 0;;
        *) error_exit "Unknown argument: $1";;
    esac
done

[ -z "$SUBSCRIPTION_ID" ]   && SUBSCRIPTION_ID=$(read_value "Function App subscription ID")
[ -z "$RESOURCE_GROUP" ]    && RESOURCE_GROUP=$(read_value "Function App resource group")
[ -z "$FUNCTION_APP_NAME" ] && FUNCTION_APP_NAME=$(read_value "Function App name")

# ---------------------------------------------------------------------------
# 1. Collect configuration
# ---------------------------------------------------------------------------
step "Sentinel Extractor — Function App Configuration"
echo "This script will configure app settings on your Function App"
echo "and generate a ZIP deployment package."

step "Sentinel Workspace Configuration"
SENTINEL_SUB_ID=$(read_value "Sentinel source subscription ID")
SENTINEL_RG=$(read_value "Sentinel source resource group")
SENTINEL_WS=$(read_value "Log Analytics workspace name")

step "Optional Resource Groups (press Enter to skip)"
LOGIC_APPS_RG=$(read_value "Logic Apps resource group" "")
DCR_RG=$(read_value "DCR resource group" "")
DCE_RG=$(read_value "DCE resource group" "")
WORKBOOKS_RG=$(read_value "Workbooks resource group" "$SENTINEL_RG")

step "Export Target Configuration"
echo "Choose where backups are exported:"
echo "  1) Azure Storage Account (default)"
echo "  2) GitHub Repository"
EXPORT_CHOICE=$(read_value "Enter choice (1 or 2)" "1")

EXPORT_TARGET="storage"
STORAGE_ACCOUNT_URL=""
STORAGE_CONTAINER="sentinel-backup"
GITHUB_REPO=""
GITHUB_BRANCH="main"
KEYVAULT_URL=""
KEYVAULT_SECRET_NAME="github-token"

if [ "$EXPORT_CHOICE" = "2" ]; then
    EXPORT_TARGET="github"
    GITHUB_REPO=$(read_value "GitHub repository (owner/repo)")
    GITHUB_BRANCH=$(read_value "GitHub branch" "main")

    step "Key Vault Configuration (for GitHub PAT)"
    echo "The GitHub token must be stored as a secret in Azure Key Vault."
    echo "The Function App's Managed Identity will be granted access to read it."
    KEYVAULT_URL=$(read_value "Key Vault URL (e.g. https://my-vault.vault.azure.net)")
    KEYVAULT_SECRET_NAME=$(read_value "Key Vault secret name for GitHub PAT" "github-token")
else
    STORAGE_ACCOUNT_URL=$(read_value "Storage account URL (e.g. https://myaccount.blob.core.windows.net)")
    STORAGE_CONTAINER=$(read_value "Storage container name" "sentinel-backup")
fi

step "Function App Internal Storage"
echo "The Functions runtime requires a storage account for leases, triggers, and state."
echo "This storage account will be accessed via Managed Identity (no connection string)."
FA_STORAGE_ACCOUNT=$(read_value "Function App storage account name (e.g. mystorageaccount)")

step "Timer Schedule"
echo "Enter a NCRONTAB expression for the timer trigger."
echo "Examples: '0 0 2 * * *' = daily at 2:00 AM, '0 0 */6 * * *' = every 6 hours"
SCHEDULE=$(read_value "Schedule" "0 0 2 * * *")

# ---------------------------------------------------------------------------
# 2. Configure Function App settings via az CLI
# ---------------------------------------------------------------------------
step "Configuring Function App application settings..."
echo "Setting az CLI subscription to $SUBSCRIPTION_ID"
az account set --subscription "$SUBSCRIPTION_ID"

# Remove legacy AzureWebJobsStorage connection string if present
az functionapp config appsettings delete \
    --name "$FUNCTION_APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --setting-names "AzureWebJobsStorage" --output none 2>/dev/null || true

az functionapp config appsettings set \
    --name "$FUNCTION_APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --settings \
        "AzureWebJobsStorage__accountName=$FA_STORAGE_ACCOUNT" \
        "AZURE_SUBSCRIPTION_ID=$SENTINEL_SUB_ID" \
        "AZURE_RESOURCE_GROUP=$SENTINEL_RG" \
        "AZURE_WORKSPACE_NAME=$SENTINEL_WS" \
        "AZURE_LOGIC_APPS_RESOURCE_GROUP=$LOGIC_APPS_RG" \
        "AZURE_DCR_RESOURCE_GROUP=$DCR_RG" \
        "AZURE_DCE_RESOURCE_GROUP=$DCE_RG" \
        "AZURE_WORKBOOKS_RESOURCE_GROUP=$WORKBOOKS_RG" \
        "EXPORT_TARGET=$EXPORT_TARGET" \
        "SCHEDULE=$SCHEDULE" \
        "AZURE_STORAGE_ACCOUNT_URL=$STORAGE_ACCOUNT_URL" \
        "AZURE_STORAGE_CONTAINER_NAME=$STORAGE_CONTAINER" \
        "KEYVAULT_URL=$KEYVAULT_URL" \
        "KEYVAULT_GITHUB_TOKEN_SECRET=$KEYVAULT_SECRET_NAME" \
        "GITHUB_REPO=$GITHUB_REPO" \
        "GITHUB_BRANCH=$GITHUB_BRANCH" \
    --output none

echo -e "${green}Application settings configured.${reset}"

# ---------------------------------------------------------------------------
# 3. Assign RBAC roles to the Function App's Managed Identity
# ---------------------------------------------------------------------------
step "Retrieving Function App Managed Identity..."

IDENTITY_JSON=$(az functionapp identity show \
    --name "$FUNCTION_APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --output json 2>/dev/null || true)

if [ -z "$IDENTITY_JSON" ] || [ "$IDENTITY_JSON" = "null" ]; then
    echo -e "${yellow}WARNING: No system-assigned managed identity found.${reset}"
    echo "Please enable system-assigned managed identity on the Function App and re-run."
else
    PRINCIPAL_ID=$(echo "$IDENTITY_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['principalId'])")
    echo "Managed Identity principal ID: $PRINCIPAL_ID"

    step "Assigning RBAC roles on Sentinel workspace..."
    SCOPE="/subscriptions/$SENTINEL_SUB_ID/resourceGroups/$SENTINEL_RG"

    echo "  Assigning Reader..."
    az role assignment create --assignee-object-id "$PRINCIPAL_ID" \
        --assignee-principal-type ServicePrincipal \
        --role "Reader" --scope "$SCOPE" --output none 2>/dev/null || true

    echo "  Assigning Microsoft Sentinel Reader..."
    az role assignment create --assignee-object-id "$PRINCIPAL_ID" \
        --assignee-principal-type ServicePrincipal \
        --role "Microsoft Sentinel Reader" --scope "$SCOPE" --output none 2>/dev/null || true

    # Logic Apps RG
    if [ -n "$LOGIC_APPS_RG" ] && [ "$LOGIC_APPS_RG" != "$SENTINEL_RG" ]; then
        LA_SCOPE="/subscriptions/$SENTINEL_SUB_ID/resourceGroups/$LOGIC_APPS_RG"
        echo "  Assigning Reader on Logic Apps RG..."
        az role assignment create --assignee-object-id "$PRINCIPAL_ID" \
            --assignee-principal-type ServicePrincipal \
            --role "Reader" --scope "$LA_SCOPE" --output none 2>/dev/null || true
    fi

    # DCR RG
    if [ -n "$DCR_RG" ] && [ "$DCR_RG" != "$SENTINEL_RG" ]; then
        DCR_SCOPE="/subscriptions/$SENTINEL_SUB_ID/resourceGroups/$DCR_RG"
        echo "  Assigning Reader on DCR RG..."
        az role assignment create --assignee-object-id "$PRINCIPAL_ID" \
            --assignee-principal-type ServicePrincipal \
            --role "Reader" --scope "$DCR_SCOPE" --output none 2>/dev/null || true
    fi

    # DCE RG
    if [ -n "$DCE_RG" ] && [ "$DCE_RG" != "$SENTINEL_RG" ]; then
        DCE_SCOPE="/subscriptions/$SENTINEL_SUB_ID/resourceGroups/$DCE_RG"
        echo "  Assigning Reader on DCE RG..."
        az role assignment create --assignee-object-id "$PRINCIPAL_ID" \
            --assignee-principal-type ServicePrincipal \
            --role "Reader" --scope "$DCE_SCOPE" --output none 2>/dev/null || true
    fi

    # Assign runtime storage RBAC roles (AzureWebJobsStorage)
    step "Assigning Functions runtime storage RBAC roles..."
    FA_STORAGE_ID=$(az storage account show --name "$FA_STORAGE_ACCOUNT" --query id --output tsv 2>/dev/null || true)
    if [ -n "$FA_STORAGE_ID" ]; then
        echo "  Assigning Storage Blob Data Owner..."
        az role assignment create --assignee-object-id "$PRINCIPAL_ID" \
            --assignee-principal-type ServicePrincipal \
            --role "Storage Blob Data Owner" --scope "$FA_STORAGE_ID" --output none 2>/dev/null || true
        echo "  Assigning Storage Queue Data Contributor..."
        az role assignment create --assignee-object-id "$PRINCIPAL_ID" \
            --assignee-principal-type ServicePrincipal \
            --role "Storage Queue Data Contributor" --scope "$FA_STORAGE_ID" --output none 2>/dev/null || true
        echo "  Assigning Storage Table Data Contributor..."
        az role assignment create --assignee-object-id "$PRINCIPAL_ID" \
            --assignee-principal-type ServicePrincipal \
            --role "Storage Table Data Contributor" --scope "$FA_STORAGE_ID" --output none 2>/dev/null || true
        echo -e "${green}Runtime storage RBAC roles assigned.${reset}"
    else
        echo -e "${yellow}WARNING: Could not find storage account '$FA_STORAGE_ACCOUNT'. Please grant Storage Blob Data Owner, Storage Queue Data Contributor, and Storage Table Data Contributor roles manually.${reset}"
    fi

    # If storage export uses a different account, assign backup RBAC roles
    if [ "$EXPORT_TARGET" = "storage" ] && [ -n "$STORAGE_ACCOUNT_URL" ]; then
        BACKUP_STORAGE_NAME=$(echo "$STORAGE_ACCOUNT_URL" | sed -E 's|https://([^.]+)\..*|\1|')
        if [ "$BACKUP_STORAGE_NAME" != "$FA_STORAGE_ACCOUNT" ]; then
            step "Assigning backup storage RBAC roles to Managed Identity..."
            BACKUP_STORAGE_ID=$(az storage account show --name "$BACKUP_STORAGE_NAME" --query id --output tsv 2>/dev/null || true)
            if [ -n "$BACKUP_STORAGE_ID" ]; then
                echo "  Assigning Storage Blob Data Contributor..."
                az role assignment create --assignee-object-id "$PRINCIPAL_ID" \
                    --assignee-principal-type ServicePrincipal \
                    --role "Storage Blob Data Contributor" --scope "$BACKUP_STORAGE_ID" --output none 2>/dev/null || true
                echo -e "${green}Backup storage RBAC role assigned.${reset}"
            else
                echo -e "${yellow}WARNING: Could not find storage account '$BACKUP_STORAGE_NAME'. Please grant 'Storage Blob Data Contributor' role manually.${reset}"
            fi
        fi
    fi

    echo -e "${green}RBAC assignments complete.${reset}"

    # Grant Key Vault access if GitHub export is selected
    if [ -n "$KEYVAULT_URL" ]; then
        step "Granting Key Vault Secrets User role to Managed Identity..."
        # Extract vault name from URL
        VAULT_NAME=$(echo "$KEYVAULT_URL" | sed -E 's|https://([^.]+)\..*|\1|')
        KV_RESOURCE_ID=$(az keyvault show --name "$VAULT_NAME" --query id --output tsv 2>/dev/null || true)
        if [ -n "$KV_RESOURCE_ID" ]; then
            az role assignment create --assignee-object-id "$PRINCIPAL_ID" \
                --assignee-principal-type ServicePrincipal \
                --role "Key Vault Secrets User" --scope "$KV_RESOURCE_ID" --output none 2>/dev/null || true
            echo -e "${green}Key Vault Secrets User role assigned.${reset}"
        else
            echo -e "${yellow}WARNING: Could not find Key Vault '$VAULT_NAME'. Please grant 'Key Vault Secrets User' role manually.${reset}"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# 4. Generate deployment ZIP package
# ---------------------------------------------------------------------------
step "Generating deployment ZIP package..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Locate repo root (script lives at repo root)
REPO_ROOT="$SCRIPT_DIR"
if [ ! -d "$REPO_ROOT/function_app" ]; then
    REPO_ROOT="$(dirname "$SCRIPT_DIR")"
fi

FA_DIR="$REPO_ROOT/function_app"
CODE_DIR="$REPO_ROOT/code"

[ -d "$FA_DIR" ]   || error_exit "function_app/ directory not found at $FA_DIR"
[ -d "$CODE_DIR" ] || error_exit "code/ directory not found at $CODE_DIR"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
ZIP_NAME="sentinel_extractor_funcapp_${TIMESTAMP}.zip"
ZIP_PATH="$REPO_ROOT/$ZIP_NAME"

# Create temporary staging directory
STAGING_DIR=$(mktemp -d)
trap 'rm -rf "$STAGING_DIR"' EXIT

# Copy function_app contents
cp -R "$FA_DIR/"* "$STAGING_DIR/"

# Copy code/ into staging
mkdir -p "$STAGING_DIR/code"
cp -R "$CODE_DIR/"* "$STAGING_DIR/code/"

# Remove local.settings.json (contains secrets)
rm -f "$STAGING_DIR/local.settings.json"

# Create ZIP
(cd "$STAGING_DIR" && zip -r "$ZIP_PATH" . -x '*.pyc' '__pycache__/*') > /dev/null

echo ""
echo -e "${green}Deployment package created: $ZIP_PATH${reset}"
echo ""
echo -e "${yellow}To deploy, use one of these methods:${reset}"
echo "  1. Azure Portal: Function App > Deployment Center > Upload ZIP"
echo "  2. Azure CLI:"
echo "     az functionapp deployment source config-zip \\"
echo "       --name $FUNCTION_APP_NAME \\"
echo "       --resource-group $RESOURCE_GROUP \\"
echo "       --src \"$ZIP_PATH\""
echo "  3. Azure Functions Core Tools (Flex Consumption):"
echo "     pip install -r requirements.txt --target .python_packages/lib/site-packages --quiet"
echo "     func azure functionapp publish $FUNCTION_APP_NAME --no-build"
echo ""

DEPLOY_NOW=$(read_value "Deploy now? (y/n)" "n")
if [ "$DEPLOY_NOW" = "y" ] || [ "$DEPLOY_NOW" = "Y" ]; then
    step "Deploying to Azure..."
    if command -v func &>/dev/null; then
        pip install -r "$STAGING_DIR/requirements.txt" --target "$STAGING_DIR/.python_packages/lib/site-packages" --quiet
        (cd "$STAGING_DIR" && func azure functionapp publish "$FUNCTION_APP_NAME" --no-build)
    else
        az functionapp deployment source config-zip \
            --name "$FUNCTION_APP_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --src "$ZIP_PATH" --output none
    fi
    echo -e "${green}Deployment complete.${reset}"
fi

step "Configuration complete!"

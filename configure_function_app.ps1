<#
.SYNOPSIS
    Configure and package the Sentinel Extractor Function App for deployment.

.DESCRIPTION
    This script configures the Azure Function App for Sentinel backup.
    It:
      1. Configures the Function App application settings (Sentinel workspace,
         DCE/DCR/Workbook/Logic Apps resource groups, export target, schedule).
      2. Assigns the Managed Identity the required RBAC roles on the source workspace.
      3. Generates a deployment ZIP package from function_app/ + code/ that can be
         imported via the Azure Portal or az functionapp deployment source config-zip.

    The Function App must already be deployed with a system-assigned Managed Identity enabled.

.PARAMETER SubscriptionId
    Azure subscription ID where the Function App is deployed.
.PARAMETER ResourceGroup
    Resource group name of the Function App.
.PARAMETER FunctionAppName
    Name of the Azure Function App.

.EXAMPLE
    ./configure_function_app.ps1 -SubscriptionId "abc-123" -ResourceGroup "my-rg" -FunctionAppName "my-funcapp"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory=$true)]
    [string]$ResourceGroup,

    [Parameter(Mandatory=$true)]
    [string]$FunctionAppName
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
# 1. Collect configuration
# ---------------------------------------------------------------------------
Write-Step "Sentinel Extractor — Function App Configuration"
Write-Host "This script will configure app settings on your Function App"
Write-Host "and generate a ZIP deployment package."
Write-Host ""

# Sentinel workspace details
Write-Step "Sentinel Workspace Configuration"
$SentinelSubscriptionId = Read-Host "Sentinel source subscription ID"
$SentinelResourceGroup  = Read-Host "Sentinel source resource group"
$SentinelWorkspaceName  = Read-Host "Log Analytics workspace name"

# Optional resource groups
Write-Step "Optional Resource Groups (press Enter to skip)"
$LogicAppsRG  = Read-ValueOrDefault "Logic Apps resource group"
$DcrRG        = Read-ValueOrDefault "DCR resource group"
$DceRG        = Read-ValueOrDefault "DCE resource group"
$WorkbooksRG  = Read-ValueOrDefault "Workbooks resource group" $SentinelResourceGroup

# Export target
Write-Step "Export Target Configuration"
Write-Host "Choose where backups are exported:"
Write-Host "  1) Azure Storage Account (default)"
Write-Host "  2) GitHub Repository"
$exportChoice = Read-ValueOrDefault "Enter choice (1 or 2)" "1"

$ExportTarget = "storage"
$StorageAccountUrl = ""
$StorageContainerName = "sentinel-backup"
$GithubRepo = ""
$GithubBranch = "main"
$KeyVaultUrl = ""
$KeyVaultSecretName = "github-token"

if ($exportChoice -eq "2") {
    $ExportTarget = "github"
    $GithubRepo   = Read-Host "GitHub repository (owner/repo)"
    $GithubBranch = Read-ValueOrDefault "GitHub branch" "main"

    Write-Step "Key Vault Configuration (for GitHub PAT)"
    Write-Host "The GitHub token must be stored as a secret in Azure Key Vault."
    Write-Host "The Function App's Managed Identity will be granted access to read it."
    $KeyVaultUrl          = Read-Host "Key Vault URL (e.g. https://my-vault.vault.azure.net)"
    $KeyVaultSecretName   = Read-ValueOrDefault "Key Vault secret name for GitHub PAT" "github-token"
} else {
    $StorageAccountUrl = Read-Host "Storage account URL (e.g. https://myaccount.blob.core.windows.net)"
    $StorageContainerName = Read-ValueOrDefault "Storage container name" "sentinel-backup"
}

# Function App internal storage
Write-Step "Function App Internal Storage"
Write-Host "The Functions runtime requires a storage account for leases, triggers, and state."
Write-Host "This storage account will be accessed via Managed Identity (no connection string)."
$FaStorageAccount = Read-Host "Function App storage account name (e.g. mystorageaccount)"

# Schedule (NCRONTAB)
Write-Step "Timer Schedule"
Write-Host "Enter a NCRONTAB expression for the timer trigger."
Write-Host "Examples: '0 0 2 * * *' = daily at 2:00 AM, '0 0 */6 * * *' = every 6 hours"
$Schedule = Read-ValueOrDefault "Schedule" "0 0 2 * * *"

# ---------------------------------------------------------------------------
# 2. Configure Function App settings via az CLI
# ---------------------------------------------------------------------------
Write-Step "Configuring Function App application settings..."

Write-Host "Setting az CLI subscription to $SubscriptionId"
az account set --subscription $SubscriptionId

# Remove legacy AzureWebJobsStorage connection string if present
az functionapp config appsettings delete `
    --name $FunctionAppName `
    --resource-group $ResourceGroup `
    --setting-names "AzureWebJobsStorage" 2>$null

# Build settings list
$settings = @(
    "AzureWebJobsStorage__accountName=$FaStorageAccount",
    "AZURE_SUBSCRIPTION_ID=$SentinelSubscriptionId",
    "AZURE_RESOURCE_GROUP=$SentinelResourceGroup",
    "AZURE_WORKSPACE_NAME=$SentinelWorkspaceName",
    "AZURE_LOGIC_APPS_RESOURCE_GROUP=$LogicAppsRG",
    "AZURE_DCR_RESOURCE_GROUP=$DcrRG",
    "AZURE_DCE_RESOURCE_GROUP=$DceRG",
    "AZURE_WORKBOOKS_RESOURCE_GROUP=$WorkbooksRG",
    "EXPORT_TARGET=$ExportTarget",
    "SCHEDULE=$Schedule",
    "AZURE_STORAGE_ACCOUNT_URL=$StorageAccountUrl",
    "AZURE_STORAGE_CONTAINER_NAME=$StorageContainerName",
    "KEYVAULT_URL=$KeyVaultUrl",
    "KEYVAULT_GITHUB_TOKEN_SECRET=$KeyVaultSecretName",
    "GITHUB_REPO=$GithubRepo",
    "GITHUB_BRANCH=$GithubBranch"
)

az functionapp config appsettings set `
    --name $FunctionAppName `
    --resource-group $ResourceGroup `
    --settings @($settings)

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to configure Function App settings." -ForegroundColor Red
    exit 1
}
Write-Host "Application settings configured." -ForegroundColor Green

# ---------------------------------------------------------------------------
# 3. Assign RBAC roles to the Function App's Managed Identity
# ---------------------------------------------------------------------------
Write-Step "Retrieving Function App Managed Identity..."

$identityJson = az functionapp identity show `
    --name $FunctionAppName `
    --resource-group $ResourceGroup `
    --output json 2>$null

if (-not $identityJson) {
    Write-Host "WARNING: No system-assigned managed identity found." -ForegroundColor Yellow
    Write-Host "Please enable system-assigned managed identity on the Function App and re-run."
} else {
    $identity = $identityJson | ConvertFrom-Json
    $principalId = $identity.principalId

    Write-Host "Managed Identity principal ID: $principalId"
    Write-Step "Assigning RBAC roles on Sentinel workspace..."

    $scope = "/subscriptions/$SentinelSubscriptionId/resourceGroups/$SentinelResourceGroup"

    # Reader on the resource group
    Write-Host "  Assigning Reader..."
    az role assignment create --assignee-object-id $principalId `
        --assignee-principal-type ServicePrincipal `
        --role "Reader" --scope $scope 2>$null

    # Microsoft Sentinel Reader on the resource group
    Write-Host "  Assigning Microsoft Sentinel Reader..."
    az role assignment create --assignee-object-id $principalId `
        --assignee-principal-type ServicePrincipal `
        --role "Microsoft Sentinel Reader" --scope $scope 2>$null

    # If Logic Apps are in a different RG, assign Reader there too
    if ($LogicAppsRG -and ($LogicAppsRG -ne $SentinelResourceGroup)) {
        $laScope = "/subscriptions/$SentinelSubscriptionId/resourceGroups/$LogicAppsRG"
        Write-Host "  Assigning Reader on Logic Apps RG..."
        az role assignment create --assignee-object-id $principalId `
            --assignee-principal-type ServicePrincipal `
            --role "Reader" --scope $laScope 2>$null
    }

    # If DCR RG is different
    if ($DcrRG -and ($DcrRG -ne $SentinelResourceGroup)) {
        $dcrScope = "/subscriptions/$SentinelSubscriptionId/resourceGroups/$DcrRG"
        Write-Host "  Assigning Reader on DCR RG..."
        az role assignment create --assignee-object-id $principalId `
            --assignee-principal-type ServicePrincipal `
            --role "Reader" --scope $dcrScope 2>$null
    }

    # If DCE RG is different
    if ($DceRG -and ($DceRG -ne $SentinelResourceGroup)) {
        $dceScope = "/subscriptions/$SentinelSubscriptionId/resourceGroups/$DceRG"
        Write-Host "  Assigning Reader on DCE RG..."
        az role assignment create --assignee-object-id $principalId `
            --assignee-principal-type ServicePrincipal `
            --role "Reader" --scope $dceScope 2>$null
    }

    # Assign runtime storage RBAC roles (AzureWebJobsStorage)
    Write-Step "Assigning Functions runtime storage RBAC roles..."
    $faStorageId = az storage account show --name $FaStorageAccount --query id --output tsv 2>$null
    if ($faStorageId) {
        Write-Host "  Assigning Storage Blob Data Owner..."
        az role assignment create --assignee-object-id $principalId `
            --assignee-principal-type ServicePrincipal `
            --role "Storage Blob Data Owner" --scope $faStorageId 2>$null
        Write-Host "  Assigning Storage Queue Data Contributor..."
        az role assignment create --assignee-object-id $principalId `
            --assignee-principal-type ServicePrincipal `
            --role "Storage Queue Data Contributor" --scope $faStorageId 2>$null
        Write-Host "  Assigning Storage Table Data Contributor..."
        az role assignment create --assignee-object-id $principalId `
            --assignee-principal-type ServicePrincipal `
            --role "Storage Table Data Contributor" --scope $faStorageId 2>$null
        Write-Host "Runtime storage RBAC roles assigned." -ForegroundColor Green
    } else {
        Write-Host "WARNING: Could not find storage account '$FaStorageAccount'. Please grant Storage Blob Data Owner, Storage Queue Data Contributor, and Storage Table Data Contributor roles manually." -ForegroundColor Yellow
    }

    # If storage export uses a different account, assign backup RBAC roles
    if ($ExportTarget -eq "storage" -and $StorageAccountUrl) {
        $backupStorageName = ([Uri]$StorageAccountUrl).Host.Split('.')[0]
        if ($backupStorageName -ne $FaStorageAccount) {
            Write-Step "Assigning backup storage RBAC roles to Managed Identity..."
            $backupStorageId = az storage account show --name $backupStorageName --query id --output tsv 2>$null
            if ($backupStorageId) {
                Write-Host "  Assigning Storage Blob Data Contributor..."
                az role assignment create --assignee-object-id $principalId `
                    --assignee-principal-type ServicePrincipal `
                    --role "Storage Blob Data Contributor" --scope $backupStorageId 2>$null
                Write-Host "Backup storage RBAC role assigned." -ForegroundColor Green
            } else {
                Write-Host "WARNING: Could not find storage account '$backupStorageName'. Please grant 'Storage Blob Data Contributor' role manually." -ForegroundColor Yellow
            }
        }
    }

    Write-Host "RBAC assignments complete." -ForegroundColor Green

    # Grant Key Vault access if GitHub export is selected
    if ($KeyVaultUrl) {
        Write-Step "Granting Key Vault Secrets User role to Managed Identity..."
        # Extract vault name from URL to build the resource scope
        $vaultName = ([Uri]$KeyVaultUrl).Host.Split('.')[0]
        # Use the Key Vault resource ID for the role assignment scope
        $kvResources = az keyvault show --name $vaultName --query id --output tsv 2>$null
        if ($kvResources) {
            az role assignment create --assignee-object-id $principalId `
                --assignee-principal-type ServicePrincipal `
                --role "Key Vault Secrets User" --scope $kvResources 2>$null
            Write-Host "Key Vault Secrets User role assigned." -ForegroundColor Green
        } else {
            Write-Host "WARNING: Could not find Key Vault '$vaultName'. Please grant 'Key Vault Secrets User' role manually." -ForegroundColor Yellow
        }
    }
}

# ---------------------------------------------------------------------------
# 4. Generate deployment ZIP package
# ---------------------------------------------------------------------------
Write-Step "Generating deployment ZIP package..."

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$projectRoot = Split-Path -Parent $scriptDir
if ($scriptDir -eq (Split-Path -Parent (Split-Path -Parent $scriptDir))) {
    $projectRoot = $scriptDir
}

# Locate directories relative to this script's location
# The script lives at the repo root; function_app/ and code/ are siblings
$repoRoot = $scriptDir
# If script is inside the repo root
if (Test-Path (Join-Path $scriptDir "function_app")) {
    $repoRoot = $scriptDir
} elseif (Test-Path (Join-Path (Split-Path -Parent $scriptDir) "function_app")) {
    $repoRoot = Split-Path -Parent $scriptDir
}

$functionAppDir = Join-Path $repoRoot "function_app"
$codeDir        = Join-Path $repoRoot "code"

if (-not (Test-Path $functionAppDir)) {
    Write-Host "ERROR: function_app/ directory not found at $functionAppDir" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $codeDir)) {
    Write-Host "ERROR: code/ directory not found at $codeDir" -ForegroundColor Red
    exit 1
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$zipName = "sentinel_extractor_funcapp_${timestamp}.zip"
$zipPath = Join-Path $repoRoot $zipName

# Create a temporary staging directory
$stagingDir = Join-Path ([System.IO.Path]::GetTempPath()) "sentinel_funcapp_staging_$timestamp"
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

# Copy function_app contents (top-level files)
Copy-Item -Path (Join-Path $functionAppDir "*") -Destination $stagingDir -Recurse -Force

# Copy code/ directory into staging
$stagingCodeDir = Join-Path $stagingDir "code"
New-Item -ItemType Directory -Path $stagingCodeDir -Force | Out-Null
Copy-Item -Path (Join-Path $codeDir "*") -Destination $stagingCodeDir -Recurse -Force

# Exclude local.settings.json from the package (contains secrets)
$localSettings = Join-Path $stagingDir "local.settings.json"
if (Test-Path $localSettings) {
    Remove-Item $localSettings
}

# Create ZIP
if (Test-Path $zipPath) { Remove-Item $zipPath }
Compress-Archive -Path (Join-Path $stagingDir "*") -DestinationPath $zipPath -Force

Write-Host ""
Write-Host "Deployment package created: $zipPath" -ForegroundColor Green
Write-Host ""
Write-Host "To deploy, use one of these methods:" -ForegroundColor Yellow
Write-Host "  1. Azure Portal: Function App > Deployment Center > Upload ZIP"
Write-Host "  2. Azure CLI:"
Write-Host "     az functionapp deployment source config-zip \" 
Write-Host "       --name $FunctionAppName \"
Write-Host "       --resource-group $ResourceGroup \"
Write-Host "       --src `"$zipPath`""
Write-Host "  3. Azure Functions Core Tools (Flex Consumption):"
Write-Host "     pip install -r requirements.txt --target .python_packages/lib/site-packages --quiet"
Write-Host "     func azure functionapp publish $FunctionAppName --no-build"
Write-Host ""

$deployNow = Read-ValueOrDefault "Deploy now? (y/n)" "n"
if ($deployNow -eq "y" -or $deployNow -eq "Y") {
    Write-Step "Deploying to Azure..."
    if (Get-Command func -ErrorAction SilentlyContinue) {
        pip install -r (Join-Path $stagingDir "requirements.txt") --target (Join-Path $stagingDir ".python_packages/lib/site-packages") --quiet
        Push-Location $stagingDir
        func azure functionapp publish $FunctionAppName --no-build
        Pop-Location
    } else {
        az functionapp deployment source config-zip `
            --name $FunctionAppName `
            --resource-group $ResourceGroup `
            --src $zipPath
    }
    Write-Host "Deployment complete." -ForegroundColor Green
}

Write-Step "Configuration complete!"
Write-Step "Configuration complete!"

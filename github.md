# GitHub Actions Deployment Guide

This document describes how to deploy the Sentinel Extractor and Restore tools as GitHub Actions workflows for automated daily backups and on-demand restoration.

---

## Overview

The GitHub Actions deployment generates a self-contained package in the `gh/` directory that includes:

| Path | Description |
|------|-------------|
| `code/sentinel_extractor.py` | Sentinel configuration extractor (copied from repo `code/`) |
| `code/sentinel_restore.py` | Sentinel configuration restorer (copied from repo `code/`) |
| `code/requirements.txt` | Python dependencies |
| `.github/workflows/sentinel-extract.yml` | Extraction workflow (scheduled + manual) |
| `.github/workflows/sentinel-restore.yml` | Restore workflow (scheduled + manual dispatch) |
| `.gitignore` | Prevents `.env` and Python cache files from being committed |

The `gh/` contents are designed to be copied into the root of any GitHub repository for immediate use.

---

## Prerequisites

1. **Python 3.8+** (GitHub Actions runners include Python by default)
2. **Azure App Registration** with the following configuration:
   - **Application (client) ID** — used as `AZURE_CLIENT_ID`
   - **Client secret** — used as `AZURE_CLIENT_SECRET`
   - **Directory (tenant) ID** — used as `AZURE_TENANT_ID`
3. **RBAC roles** assigned to the App Registration (service principal):

   | Operation | Required Roles | Scope |
   |-----------|----------------|-------|
   | Extraction | `Reader`, `Microsoft Sentinel Reader` | Sentinel resource group |
   | Restoration | `Reader`, `Microsoft Sentinel Contributor` | Target resource group |
   | Restoration (Logic Apps) | `Logic App Contributor` | Target Logic Apps resource group |
   | Restoration (DCR/DCE) | `Monitoring Contributor` | Target DCR/DCE resource group |

4. **GitHub repository** to host the workflows
5. **GitHub Environment** for storing secrets securely (supports protection rules and approval gates)

---

## Step 1 — Run the Configuration Script

### Bash (macOS, Linux, WSL)

```bash
./configure_gh_workflow.sh [--env-name <environment-name>]
```

### PowerShell (Windows, macOS, Linux)

```powershell
./configure_gh_workflow.ps1 [-EnvName <environment-name>]
```

### Script Prompts

The script will prompt for the following values:

#### Source Workspace Configuration

| Prompt | Description | Required |
|--------|-------------|----------|
| Sentinel source subscription ID | Azure subscription containing the Sentinel workspace | Yes |
| Sentinel source resource group | Resource group containing the workspace | Yes |
| Log Analytics workspace name | Name of the Log Analytics workspace | Yes |
| Logic Apps resource group | Resource group for Logic Apps (if different) | No |
| DCR resource group | Resource group for Data Collection Rules (if different) | No |
| DCE resource group | Resource group for Data Collection Endpoints (if different) | No |
| Workbooks resource group | Resource group for Workbooks (defaults to workspace RG) | No |

#### Restore Target Configuration

| Prompt | Description | Default |
|--------|-------------|---------|
| Target subscription ID | Subscription for restore target | Same as source |
| Target resource group | Resource group for restore target | Same as source |
| Target workspace name | Workspace name for restore target | Same as source |
| Target Logic Apps RG | Target RG for Logic Apps | Empty |
| Target DCR RG | Target RG for DCRs | Empty |
| Target DCE RG | Target RG for DCEs | Empty |
| Target Workbooks RG | Target RG for Workbooks | Same as target RG |
| Target Azure region | Azure region for Logic Apps, DCRs, DCEs | Empty |

#### Schedule Configuration

| Prompt | Description | Default |
|--------|-------------|---------|
| Extraction schedule | Cron expression (5-field, UTC) for daily extraction | `0 2 * * *` (daily at 2 AM) |
| Restore schedule | Cron expression for scheduled restores (leave empty for manual only) | Empty |

### Example

```bash
$ ./configure_gh_workflow.sh --env-name sentinel-prod

==> Sentinel Extractor — GitHub Actions Configuration
...

==> Source Sentinel Workspace Configuration
Sentinel source subscription ID: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
Sentinel source resource group: rg-sentinel-prod
Log Analytics workspace name: la-sentinel-prod

==> Optional Source Resource Groups (press Enter to skip)
Logic Apps resource group []: rg-logic-apps
DCR resource group []: 
DCE resource group []: 
Workbooks resource group [rg-sentinel-prod]: 

==> Restore Target Configuration
Target subscription ID [aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee]: 
Target resource group [rg-sentinel-prod]: 
Target workspace name [la-sentinel-prod]: 
...

==> Extraction Schedule
Extraction schedule [0 2 * * *]: 

==> Restore Schedule (optional)
Restore schedule (empty = manual only) []: 

==> Generating gh/ directory...
...
==> GitHub Actions package generated successfully!
```

---

## Step 2 — Import into Your Repository

Copy the generated `gh/` contents into the root of your target GitHub repository:

```bash
# From the repo root where you ran the configure script
cp -r gh/.github  /path/to/your/target-repo/
cp -r gh/code     /path/to/your/target-repo/
cp    gh/.gitignore /path/to/your/target-repo/
```

Or, if the target repo _is_ the current repo, simply move the files:

```bash
cp -r gh/.github .
cp -r gh/code .
cp gh/.gitignore .
```

---

## Step 3 — Configure GitHub Environment Secrets

1. Navigate to your GitHub repository: **Settings → Environments → New environment**
2. Create an environment named `sentinel-prod` (or the name you chose during configuration)
3. Add the following **secrets** to the environment:

| Secret | Description |
|--------|-------------|
| `AZURE_TENANT_ID` | Azure AD tenant ID |
| `AZURE_CLIENT_ID` | App Registration client ID |
| `AZURE_CLIENT_SECRET` | App Registration client secret |

> **Optional:** If the GitHub CLI (`gh`) is installed, the configuration script can set up the environment and secrets automatically.

### Optional: Environment Protection Rules

GitHub Environments support protection rules that add safety to your workflows:

- **Required reviewers** — require approval before a workflow runs against the environment
- **Wait timer** — add a delay before deployment
- **Deployment branches** — restrict which branches can use the environment

These are especially useful for the restore workflow, which modifies your Sentinel configuration.

---

## Step 4 — Enable and Verify Workflows

1. Push the changes to your GitHub repository
2. Navigate to **Actions** in your repository
3. If workflows are not yet enabled, click **"I understand my workflows, go ahead and enable them"**
4. Verify the extraction workflow appears as **"Sentinel Configuration Extract"**
5. Verify the restore workflow appears as **"Sentinel Configuration Restore"**

### Manual Test Run

1. Go to **Actions → Sentinel Configuration Extract**
2. Click **"Run workflow"** → select the branch → click **"Run workflow"**
3. Monitor the workflow run for successful completion
4. Verify that the `output/` directory was committed with your Sentinel configuration backup

---

## Extraction Workflow

### Trigger

| Trigger | Description |
|---------|-------------|
| `schedule` | Runs on the configured cron schedule (default: daily at 2 AM UTC) |
| `workflow_dispatch` | Manual trigger via the Actions UI or GitHub API |

### Behavior

1. Checks out the repository
2. Sets up Python 3.11 with pip caching
3. Installs dependencies from `code/requirements.txt`
4. Runs `sentinel_extractor.py` with credentials from GitHub Environment secrets
5. Commits and pushes any changed files in `output/` back to the repository

### Output Structure

```
output/
└── <subscription-id>/
    └── <workspace-name>/
        ├── AlertRules/
        ├── AutomationRules/
        ├── SummaryRules/
        ├── Hunting/
        │   └── HuntingQueries/
        ├── WorkspaceFunctions/
        ├── SavedQueries/
        ├── DataCollectionRules/
        ├── DataCollectionEndpoints/
        ├── Workbooks/
        ├── LogicApps/
        ├── Watchlists/
        ├── CustomTables/
        ├── ContentPackages/
        ├── DataConnectors/
        ├── ProductSettings/
        ├── ThreatIntelligence/
        ├── IAM/
        ├── logs/
        ├── table_retention.json
        └── .file_tracker.json
```

### Change Detection

The extractor uses a `.file_tracker.json` file to detect changes between runs. Only modified resources are updated. Previous versions of changed files are stored in `older_versions/` subdirectories within each resource folder.

---

## Restore Workflow

### Trigger

| Trigger | Description |
|---------|-------------|
| `schedule` | Runs on the configured cron schedule (if configured; disabled by default) |
| `workflow_dispatch` | Manual trigger with configurable inputs |

### Workflow Dispatch Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `target_subscription_id` | Override the target subscription ID | Configured default |
| `target_resource_group` | Override the target resource group | Configured default |
| `target_workspace_name` | Override the target workspace name | Configured default |
| `restore_flags` | Flags controlling which resource types to restore | `--restore-all` |
| `generate_new_id` | Generate new GUIDs (avoids 409 soft-delete conflicts) | `false` |
| `logic_app_mode` | Logic App restore mode: `same-tenant` or `new-environment` | `same-tenant` |

### Available Restore Flags

Use one or more of these in the `restore_flags` input:

| Flag | Resource Type |
|------|---------------|
| `--restore-all` | All implemented resource types |
| `--restore-alert-rules` | Alert Rules |
| `--restore-automation-rules` | Automation Rules |
| `--restore-summary-rules` | Summary Rules |
| `--restore-hunting` | Hunting queries and relations |
| `--restore-workspace-functions` | Workspace Functions (parsers) |
| `--restore-dcr` | Data Collection Rules |
| `--restore-dce` | Data Collection Endpoints |
| `--restore-logic-apps` | Logic Apps |
| `--restore-custom-tables` | Custom Tables |
| `--restore-table-retention` | Table Retention settings |
| `--restore-product-settings` | Product Settings |
| `--restore-data-connectors` | Data Connectors |
| `--restore-content-packages` | Content Packages (solutions) |
| `--restore-threat-intelligence` | Threat Intelligence indicators |

### Example: Restore Only Alert Rules with New IDs

1. Go to **Actions → Sentinel Configuration Restore**
2. Click **"Run workflow"**
3. Set `restore_flags` to `--restore-alert-rules`
4. Check `generate_new_id` to `true`
5. Click **"Run workflow"**

### Restore Phases

When using `--restore-all`, resources are restored in dependency order:

**Phase 1 — Prerequisites:**
- Custom Tables, Table Retention, Content Packages, Data Connectors, Product Settings

**Phase 2 — Dependent Resources:**
- Alert Rules, Automation Rules, Summary Rules, Hunting, Workspace Functions, DCRs, DCEs, Logic Apps, Threat Intelligence

---

## Cross-Tenant Restoration

To restore to a different Azure tenant:

1. Create an App Registration in the **target tenant** with `Microsoft Sentinel Contributor` and `Reader` roles
2. Create a separate GitHub Environment (e.g., `sentinel-dr`) with the target tenant's credentials
3. Modify the restore workflow's `environment:` field to use the new environment name
4. Set the `logic_app_mode` to `new-environment` (API connections cannot be shared across tenants)

---

## Troubleshooting

### Workflow does not run on schedule

- GitHub disables scheduled workflows on repositories with no activity for 60 days. Push a commit or manually trigger the workflow to re-enable.
- Cron schedules run in UTC. Verify your cron expression accounts for timezone differences.

### Authentication fails (401/403)

- Verify the App Registration secrets have not expired
- Confirm the secrets are stored in the correct GitHub Environment (not just repository secrets)
- Check that the workflow's `environment:` field matches the environment name where secrets are stored
- Verify RBAC role assignments on the Azure resource groups

### Extraction produces no output

- Check the workflow logs for API errors (e.g., 403 Forbidden indicates missing RBAC roles)
- Run the extractor locally with `--debug` to see detailed API responses:
  ```bash
  python code/sentinel_extractor.py --debug
  ```

### Restore fails with 409 Conflict

- Azure enforces a soft-delete cooldown on some resources (e.g., Alert Rules). Enable `generate_new_id` in the workflow dispatch to assign fresh GUIDs and avoid the conflict.

### Git push fails (conflict)

- If the extraction workflow's git push fails due to concurrent changes, re-run the workflow. The checkout step will pull the latest state.

---

## Security Considerations

- **Credentials** are stored exclusively in GitHub Environment secrets — never in workflow YAML, code, or repository files
- **Credentials** are passed to Python via environment variables (not CLI arguments), avoiding exposure in process listings
- **Workflow permissions** follow the principle of least privilege:
  - Extraction: `contents: write` (to commit output)
  - Restore: `contents: read` (read-only access to backup files)
- **Restore flags** are validated against an allowlist pattern before execution to prevent injection
- **GitHub Environments** support protection rules (required reviewers, wait timers) for additional safety on restoration workflows
- **`.gitignore`** prevents `.env` files and Python caches from being committed

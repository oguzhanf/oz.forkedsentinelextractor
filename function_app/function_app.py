"""
Azure Function App — Timer-triggered Sentinel Configuration Extractor.

Uses Managed Identity (DefaultAzureCredential) to authenticate.
Exports backup to Azure Blob Storage or pushes to a GitHub repository,
depending on the EXPORT_TARGET application setting.
"""

import io
import json
import logging
import os
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import azure.functions as func
import requests

# Add the code/ directory to the path so we can import sentinel_extractor.
# In deployed ZIP layout, code/ is a sibling of function_app.py inside wwwroot/.
# In local dev (repo layout), code/ is at ../code relative to function_app/.
_deployed = Path(__file__).resolve().parent / "code"
_repo = Path(__file__).resolve().parent.parent / "code"
_root = _deployed if _deployed.is_dir() else _repo
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from sentinel_extractor import run_extraction  # noqa: E402

app = func.FunctionApp()

log = logging.getLogger(__name__)


def _build_config() -> dict:
    """Build the extraction config from Function App application settings."""
    return {
        "use_managed_identity": True,
        "subscription_id": os.environ["AZURE_SUBSCRIPTION_ID"],
        "resource_group": os.environ["AZURE_RESOURCE_GROUP"],
        "workspace_name": os.environ["AZURE_WORKSPACE_NAME"],
        "logic_apps_resource_group": os.getenv("AZURE_LOGIC_APPS_RESOURCE_GROUP", ""),
        "dcr_resource_group": os.getenv("AZURE_DCR_RESOURCE_GROUP", ""),
        "dce_resource_group": os.getenv("AZURE_DCE_RESOURCE_GROUP", ""),
        "workbooks_resource_group": os.getenv(
            "AZURE_WORKBOOKS_RESOURCE_GROUP",
            os.environ.get("AZURE_RESOURCE_GROUP", ""),
        ),
    }


def _export_to_storage(output_root: Path) -> None:
    """Upload all extracted files to Azure Blob Storage as a ZIP archive."""
    try:
        from azure.identity import DefaultAzureCredential
        from azure.storage.blob import BlobServiceClient
    except ImportError as exc:
        raise ImportError(
            "azure-storage-blob and azure-identity are required for storage export. "
            "Add azure-storage-blob to requirements.txt."
        ) from exc

    container_name = os.getenv("AZURE_STORAGE_CONTAINER_NAME", "sentinel-backup")
    account_url = os.environ["AZURE_STORAGE_ACCOUNT_URL"]
    credential = DefaultAzureCredential()
    blob_service = BlobServiceClient(account_url=account_url, credential=credential)

    container_client = blob_service.get_container_client(container_name)
    try:
        container_client.get_container_properties()
    except Exception:
        container_client.create_container()

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    blob_name = f"sentinel_backup_{timestamp}.zip"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in output_root.rglob("*"):
            if file_path.is_file():
                arcname = str(file_path.relative_to(output_root.parent.parent))
                zf.write(file_path, arcname)
    buf.seek(0)

    blob_client = container_client.get_blob_client(blob_name)
    blob_client.upload_blob(buf, overwrite=True)
    log.info("Uploaded backup to blob: %s/%s", container_name, blob_name)


def _get_github_token() -> str:
    """Retrieve the GitHub PAT from Azure Key Vault using Managed Identity."""
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.secrets import SecretClient

    vault_url = os.environ["KEYVAULT_URL"]
    secret_name = os.getenv("KEYVAULT_GITHUB_TOKEN_SECRET", "github-token")

    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=vault_url, credential=credential)
    secret = client.get_secret(secret_name)
    log.info("Retrieved GitHub token from Key Vault: %s (secret: %s)", vault_url, secret_name)
    return secret.value


def _export_to_github(output_root: Path) -> None:
    """Push extracted files to a GitHub repository using the GitHub API."""
    token = _get_github_token()
    repo = os.environ["GITHUB_REPO"]  # e.g. "owner/repo"
    branch = os.getenv("GITHUB_BRANCH", "main")

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    api_base = f"https://api.github.com/repos/{repo}"

    import base64

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    commit_message = f"Sentinel backup {timestamp}"

    # Get the current commit SHA of the branch
    ref_resp = requests.get(f"{api_base}/git/ref/heads/{branch}", headers=headers, timeout=30)
    ref_resp.raise_for_status()
    base_sha = ref_resp.json()["object"]["sha"]

    # Get the base tree
    commit_resp = requests.get(f"{api_base}/git/commits/{base_sha}", headers=headers, timeout=30)
    commit_resp.raise_for_status()
    base_tree_sha = commit_resp.json()["tree"]["sha"]

    # Build tree entries from all files
    tree_entries = []
    for file_path in output_root.rglob("*"):
        if file_path.is_file():
            rel_path = str(file_path.relative_to(output_root.parent.parent))
            content_bytes = file_path.read_bytes()
            # Create a blob for each file
            blob_resp = requests.post(
                f"{api_base}/git/blobs",
                headers=headers,
                json={
                    "content": base64.b64encode(content_bytes).decode("ascii"),
                    "encoding": "base64",
                },
                timeout=30,
            )
            blob_resp.raise_for_status()
            tree_entries.append({
                "path": rel_path,
                "mode": "100644",
                "type": "blob",
                "sha": blob_resp.json()["sha"],
            })

    # Create a new tree
    tree_resp = requests.post(
        f"{api_base}/git/trees",
        headers=headers,
        json={"base_tree": base_tree_sha, "tree": tree_entries},
        timeout=60,
    )
    tree_resp.raise_for_status()
    new_tree_sha = tree_resp.json()["sha"]

    # Create a new commit
    new_commit_resp = requests.post(
        f"{api_base}/git/commits",
        headers=headers,
        json={
            "message": commit_message,
            "tree": new_tree_sha,
            "parents": [base_sha],
        },
        timeout=30,
    )
    new_commit_resp.raise_for_status()
    new_commit_sha = new_commit_resp.json()["sha"]

    # Update the branch reference
    update_resp = requests.patch(
        f"{api_base}/git/refs/heads/{branch}",
        headers=headers,
        json={"sha": new_commit_sha},
        timeout=30,
    )
    update_resp.raise_for_status()
    log.info("Pushed backup to GitHub: %s@%s (%s)", repo, branch, new_commit_sha[:8])


def _seed_from_github(output_root: Path) -> None:
    """Download the tracker and existing files from GitHub so change detection works."""
    import base64

    token = _get_github_token()
    repo = os.environ["GITHUB_REPO"]
    branch = os.getenv("GITHUB_BRANCH", "main")

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    api_base = f"https://api.github.com/repos/{repo}"

    # Determine the path prefix in the repo that corresponds to output_root.
    # The extractor writes to: output_root = tmpdir/subscription_id/workspace_name
    # When pushed, paths are relative to output_root.parent.parent (the tmpdir),
    # so repo files live under: subscription_id/workspace_name/...
    repo_prefix = str(
        output_root.relative_to(output_root.parent.parent)
    )

    def _download_tree(prefix: str) -> None:
        """Recursively download files from a GitHub tree path into output_root."""
        resp = requests.get(
            f"{api_base}/contents/{prefix}",
            headers=headers,
            params={"ref": branch},
            timeout=30,
        )
        if resp.status_code == 404:
            log.info("No existing backup found in GitHub at %s", prefix)
            return
        resp.raise_for_status()

        items = resp.json()
        if not isinstance(items, list):
            items = [items]

        for item in items:
            rel = item["path"]
            local_path = output_root.parent.parent / rel

            if item["type"] == "dir":
                local_path.mkdir(parents=True, exist_ok=True)
                _download_tree(rel)
            elif item["type"] == "file":
                local_path.parent.mkdir(parents=True, exist_ok=True)
                blob_resp = requests.get(
                    item["url"],
                    headers=headers,
                    timeout=30,
                )
                blob_resp.raise_for_status()
                content = base64.b64decode(blob_resp.json()["content"])
                local_path.write_bytes(content)

    output_root.mkdir(parents=True, exist_ok=True)
    _download_tree(repo_prefix)
    log.info("Seeded output directory from GitHub (%s)", repo_prefix)


@app.timer_trigger(
    schedule="%SCHEDULE%",
    arg_name="timer",
    run_on_startup=False,
    use_monitor=True,
)
def sentinel_backup_timer(timer: func.TimerRequest) -> None:
    """Timer-triggered function that runs the Sentinel extractor."""
    if timer.past_due:
        log.warning("Timer is past due — running extraction now.")

    log.info("Sentinel backup function triggered at %s", datetime.now(timezone.utc).isoformat())

    cfg = _build_config()

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg["output_dir"] = tmpdir

        export_target = os.getenv("EXPORT_TARGET", "storage").lower()

        # Seed output directory from GitHub so change detection works
        if export_target == "github":
            seed_root = (
                Path(tmpdir) / cfg["subscription_id"] / cfg["workspace_name"]
            )
            try:
                _seed_from_github(seed_root)
            except Exception:
                log.exception("Failed to seed from GitHub — running full extraction")

        result = run_extraction(cfg)

        total_saved = result["total_saved"]
        log.info("Extraction complete. Total files saved/updated: %d", total_saved)

        output_root = (
            Path(tmpdir) / cfg["subscription_id"] / cfg["workspace_name"]
        )

        if not output_root.exists():
            log.warning("No output produced — nothing to export.")
            return

        export_target = os.getenv("EXPORT_TARGET", "storage").lower()

        if export_target == "github":
            try:
                _export_to_github(output_root)
            except Exception:
                log.exception("GitHub export failed")
                raise
        else:
            try:
                _export_to_storage(output_root)
            except Exception:
                log.exception("Storage export failed")
                raise

    log.info("Sentinel backup function completed successfully.")

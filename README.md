# gMSA-AD_Query-Via-Scheduled-Task-
Tests whether a gMSA can read AD attributes for a target account by running a PowerShell AD query as the gMSA via a temporary scheduled task.
[README.md](https://github.com/user-attachments/files/25578772/README.md)
# Test-gMSAPermissions.ps1

Tests whether a gMSA can read AD attributes for a target account by running a PowerShell AD query as the gMSA via a temporary scheduled task. Useful when BloodHound Enterprise is not reflecting the correct attribute values after collection, and you need to verify what the gMSA can actually see in AD.

---

## Why This Exists

gMSAs have no password and cannot be used with `RunAs` or interactive logon. A scheduled task is the only practical way to execute code in the context of a gMSA to test its AD read permissions.

---

## Configuration

All settings are at the top of the script:

| Variable | Description |
|---|---|
| `$Account` | The AD account to query (UPN, SamAccountName, or DN) |
| `$gMSA_Source` | `"auto"` detects gMSA from the service, `"manual"` uses `$gMSA_Manual` |
| `$gMSA_ServiceName` | Windows service name to detect the gMSA from (e.g. `SharpHoundEnterprise`) |
| `$gMSA_Manual` | Hardcoded gMSA fallback — format: `DOMAIN\accountname$` |
| `$AD_Query` | The AD query to run as the gMSA — do not include `\| Out-File` |

---

## Usage

```powershell
# Run from an elevated PowerShell session on the collector/delegator machine
.\Test-gMSAPermissions.ps1
```

Output is logged to screen (colour coded) and saved to `C:\temp\gmsa_test_log.txt`.

---

## What It Checks

1. Resolves the gMSA from the service or manual override
2. Verifies the gMSA exists in AD
3. Checks `SeBatchLogonRight` (required for scheduled tasks)
4. Verifies the ActiveDirectory PS module is available, installs via RSAT if not
5. Registers, runs, and monitors the scheduled task
6. Captures Task Scheduler event log entries
7. Outputs the query result or any errors
8. Cleans up the task and temp files

---

## Requirements

- Must be run as a local administrator on the target machine
- Machine must be domain-joined with AD connectivity
- gMSA must be permitted to run scheduled tasks (`SeBatchLogonRight`)

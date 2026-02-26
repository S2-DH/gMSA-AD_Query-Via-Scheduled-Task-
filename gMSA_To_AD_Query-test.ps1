# ============================================================
#  Test-gMSAPermissions.ps1
#  Tests whether a gMSA can read AD attributes for a target account
# ============================================================

# ============================================================
#  CONFIGURATION — EDIT THIS SECTION
# ============================================================

# --- ACCOUNT TO CHECK ---
# The AD account whose attributes you want to query.
# Accepts UPN, SamAccountName, or DN.
$Account = "<ACCOUNT_@_DOMAIN>"

# --- gMSA SOURCE ---
# "auto"   — detects the gMSA from the service defined in $gMSA_ServiceName below
# "manual" — uses the value set in $gMSA_Manual below
$gMSA_Source = "auto"

# --- SERVICE NAME (used when $gMSA_Source = "auto") ---
# The Windows service that runs as your gMSA on this machine.
# BHE/SharpHound service names:
#   "SHDelegator"
$gMSA_ServiceName = "SHDelegator"

# --- gMSA MANUAL OVERRIDE (used when $gMSA_Source = "manual") ---
# Format: DOMAIN\accountname$
$gMSA_Manual = "<DOMAIN\ACCOUNT TO TEST (gMSA ACCOUNT)>"

# --- TASK / OUTPUT SETTINGS ---
$TaskName   = "TestgMSAPermissions"
$OutputFile = "C:\temp\gmsa_test.txt"
$LogFile    = "C:\temp\gmsa_test_log.txt"
$SleepSecs  = 10

# ============================================================
#  AD QUERY — SET THE QUERY YOU WANT TO RUN AS THE gMSA
#  Do NOT include "| Out-File" — that is handled automatically.
#  $Account is substituted automatically into the default query.
#
#  Examples:
#    "Get-ADUser '$Account' -Properties userAccountControl | Select-Object Name, userAccountControl"
#    "Get-ADObject -Filter {UserPrincipalName -eq '$Account'} -Properties userAccountControl, objectClass | Select-Object Name, objectClass, userAccountControl"
#    "Get-ADServiceAccount 't0_gMSA_SHSA`$' -Properties *"
#    "Get-ADGroup 'Domain Admins' -Properties Members | Select-Object Name, Members"
#    "Get-ADComputer 'DC01' -Properties * | Select-Object Name, OperatingSystem, Enabled"
# ============================================================
$AD_Query = "Get-ADObject -Filter {UserPrincipalName -eq '$Account'} -Properties userAccountControl, objectClass | Select-Object Name, SamAccountName, objectClass, userAccountControl"


# ============================================================
# LOGGING FUNCTION
# ============================================================
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","SUCCESS","SECTION")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colour = switch ($Level) {
        "INFO"    { "Cyan" }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red" }
        "SUCCESS" { "Green" }
        "SECTION" { "Magenta" }
    }
    $line = "[$timestamp][$Level] $Message"
    Write-Host $line -ForegroundColor $colour
    Add-Content -Path $LogFile -Value $line
}

# ============================================================
# INITIALISE
# ============================================================
New-Item -ItemType Directory -Force -Path "C:\temp" | Out-Null
"" | Out-File $LogFile -Force

Write-Log "================================================" -Level SECTION
Write-Log " gMSA Permissions Test Starting" -Level SECTION
Write-Log "================================================" -Level SECTION

# ============================================================
# STEP 0 - RESOLVE gMSA IDENTITY (AUTO OR MANUAL)
# ============================================================
Write-Log "------------------------------------------------" -Level SECTION
Write-Log "STEP 0 : Resolving gMSA Identity" -Level SECTION

if ($gMSA_Source -eq "auto") {
    Write-Log "gMSA Source : AUTO — detecting from service '$gMSA_ServiceName'" -Level INFO
    try {
        $svc = Get-WmiObject Win32_Service -Filter "Name='$gMSA_ServiceName'" -ErrorAction Stop
        if ($svc) {
            $gMSA = $svc.StartName
            Write-Log "Service '$gMSA_ServiceName' found." -Level SUCCESS
            Write-Log "Service runs as : $gMSA" -Level SUCCESS

            # Sanity check — must be a domain account, not LocalSystem/blank
            if (-not $gMSA -or $gMSA -match "^(LocalSystem|NT AUTHORITY|LOCAL SERVICE|NETWORK SERVICE)$" -or $gMSA -eq "") {
                Write-Log "Service StartName '$gMSA' is not a domain gMSA. Falling back to manual value." -Level WARN
                $gMSA = $gMSA_Manual
                Write-Log "Using manual gMSA : $gMSA" -Level WARN
            }
        } else {
            Write-Log "Service '$gMSA_ServiceName' not found on this machine. Falling back to manual value." -Level WARN
            $gMSA = $gMSA_Manual
            Write-Log "Using manual gMSA : $gMSA" -Level WARN
        }
    } catch {
        Write-Log "Failed to query service '$gMSA_ServiceName': $_" -Level ERROR
        Write-Log "Falling back to manual gMSA value." -Level WARN
        $gMSA = $gMSA_Manual
    }
} else {
    $gMSA = $gMSA_Manual
    Write-Log "gMSA Source : MANUAL" -Level INFO
    Write-Log "Using gMSA  : $gMSA" -Level INFO
}

Write-Log "------------------------------------------------" -Level SECTION
Write-Log "Account Under Test : $Account"
Write-Log "gMSA               : $gMSA"
Write-Log "Task Name          : $TaskName"
Write-Log "Output File        : $OutputFile"
Write-Log "Log File           : $LogFile"
Write-Log "AD Query           : $AD_Query"

# ============================================================
# STEP 1 - CHECK gMSA EXISTS AND CAN RUN AS SCHEDULED TASK
# ============================================================
Write-Log "------------------------------------------------" -Level SECTION
Write-Log "STEP 1 : Checking gMSA account exists in AD" -Level SECTION

try {
    $gmsaName = $gMSA.Split("\")[1]
    $gmsaObj  = Get-ADServiceAccount -Identity $gmsaName -Properties * -ErrorAction Stop
    Write-Log "gMSA found       : $($gmsaObj.DistinguishedName)" -Level SUCCESS
    Write-Log "gMSA Enabled     : $($gmsaObj.Enabled)"
    Write-Log "gMSA objectClass : $($gmsaObj.objectClass)"
} catch {
    Write-Log "Could not find gMSA '$gMSA' in AD. Error: $_" -Level ERROR
    Write-Log "Ensure the gMSA exists and this script is run with sufficient AD read rights." -Level WARN
}

Write-Log "Checking 'Log on as a batch job' right for $gMSA ..."
try {
    & secedit /export /cfg "$env:TEMP\secedit_export.cfg" /quiet
    $batchRight = Select-String -Path "$env:TEMP\secedit_export.cfg" -Pattern "SeBatchLogonRight"
    if ($batchRight) {
        Write-Log "SeBatchLogonRight entry: $($batchRight.Line)" -Level INFO
        if ($batchRight.Line -match [regex]::Escape($gmsaName)) {
            Write-Log "gMSA has 'Log on as a batch job' right." -Level SUCCESS
        } else {
            Write-Log "gMSA may NOT be in SeBatchLogonRight — task could fail silently." -Level WARN
        }
    } else {
        Write-Log "Could not determine SeBatchLogonRight from secedit export." -Level WARN
    }
} catch {
    Write-Log "secedit check failed: $_" -Level WARN
}

# ============================================================
# STEP 2 - CHECK / INSTALL ACTIVEDIRECTORY MODULE
# ============================================================
Write-Log "------------------------------------------------" -Level SECTION
Write-Log "STEP 2 : Checking ActiveDirectory module" -Level SECTION

$adModule = Get-Module -ListAvailable -Name ActiveDirectory
if ($adModule) {
    Write-Log "ActiveDirectory module found : Version $($adModule.Version)" -Level SUCCESS
} else {
    Write-Log "ActiveDirectory module NOT found. Attempting install via RSAT..." -Level WARN
    try {
        Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ErrorAction Stop
        Write-Log "RSAT ActiveDirectory module installed successfully." -Level SUCCESS
    } catch {
        Write-Log "Failed to install RSAT AD module: $_" -Level ERROR
        Write-Log "Install manually: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -Level WARN
    }
}

# ============================================================
# STEP 3 - CLEAN UP ANY EXISTING TASK
# ============================================================
Write-Log "------------------------------------------------" -Level SECTION
Write-Log "STEP 3 : Cleaning up any existing task named '$TaskName'" -Level SECTION

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Log "Existing task removed." -Level WARN
} else {
    Write-Log "No existing task found — OK to proceed." -Level INFO
}

# ============================================================
# STEP 4 - REGISTER SCHEDULED TASK
# ============================================================
Write-Log "------------------------------------------------" -Level SECTION
Write-Log "STEP 4 : Registering Scheduled Task as $gMSA" -Level SECTION

$psCommand = @"
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    `$result = $AD_Query -ErrorAction Stop
    if (`$result) {
        `$result | Out-File '$OutputFile'
    } else {
        "Query returned no results. Query was: $AD_Query" | Out-File '$OutputFile'
    }
} catch {
    "ERROR: `$_`nQuery was: $AD_Query" | Out-File '$OutputFile'
}
"@

$encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($psCommand))

try {
    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -EncodedCommand $encodedCommand"
    $principal = New-ScheduledTaskPrincipal -UserId $gMSA -LogonType Password
    Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Force -ErrorAction Stop | Out-Null
    Write-Log "Scheduled task '$TaskName' registered successfully." -Level SUCCESS
} catch {
    Write-Log "Failed to register scheduled task: $_" -Level ERROR
    exit 1
}

# ============================================================
# STEP 5 - VERIFY TASK REGISTERED CORRECTLY
# ============================================================
Write-Log "------------------------------------------------" -Level SECTION
Write-Log "STEP 5 : Verifying task registration" -Level SECTION

$taskCheck = Get-ScheduledTask -TaskName $TaskName | Select-Object TaskName, State, @{Name="UserId";Expression={$_.Principal.UserId}}
Write-Log "Task Name  : $($taskCheck.TaskName)"
Write-Log "Task State : $($taskCheck.State)"
Write-Log "Runs As    : $($taskCheck.UserId)"

# ============================================================
# STEP 6 - RUN THE TASK
# ============================================================
Write-Log "------------------------------------------------" -Level SECTION
Write-Log "STEP 6 : Starting task..." -Level SECTION

try {
    Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    Write-Log "Task started. Waiting $SleepSecs seconds for completion..." -Level INFO
} catch {
    Write-Log "Failed to start task: $_" -Level ERROR
    exit 1
}

for ($i = $SleepSecs; $i -gt 0; $i--) {
    Write-Host "`r  Waiting... $i seconds remaining   " -NoNewline -ForegroundColor DarkCyan
    Start-Sleep -Seconds 1
}
Write-Host ""

# ============================================================
# STEP 7 - CHECK TASK RESULT AND EVENT LOG
# ============================================================
Write-Log "------------------------------------------------" -Level SECTION
Write-Log "STEP 7 : Checking task result and event log" -Level SECTION

$taskInfo = Get-ScheduledTaskInfo -TaskName $TaskName
Write-Log "Last Run Time   : $($taskInfo.LastRunTime)"
Write-Log "Last Run Result : $($taskInfo.LastTaskResult)"

if ($taskInfo.LastTaskResult -eq 0) {
    Write-Log "Task completed successfully (return code 0)." -Level SUCCESS
} else {
    $hexCode = "0x{0:X8}" -f $taskInfo.LastTaskResult
    Write-Log "Task returned non-zero code: $($taskInfo.LastTaskResult) ($hexCode)" -Level ERROR
}

Write-Log "Pulling Task Scheduler events for '$TaskName'..." -Level INFO
try {
    $events = Get-WinEvent -LogName "Microsoft-Windows-TaskScheduler/Operational" -ErrorAction Stop |
              Where-Object { $_.Message -match $TaskName } |
              Select-Object -Last 10
    if ($events) {
        foreach ($evt in $events) {
            $evtLevel = if ($evt.LevelDisplayName) { $evt.LevelDisplayName } else { "Info" }
            Write-Log "  [Event $($evt.Id)][$evtLevel] $($evt.TimeCreated) — $($evt.Message.Split([Environment]::NewLine)[0])" -Level INFO
        }
    } else {
        Write-Log "No Task Scheduler events found for '$TaskName'." -Level WARN
    }
} catch {
    Write-Log "Could not read Task Scheduler event log: $_" -Level WARN
}

# ============================================================
# STEP 8 - OUTPUT RESULTS
# ============================================================
Write-Log "------------------------------------------------" -Level SECTION
Write-Log "STEP 8 : Reading output file" -Level SECTION

if (Test-Path $OutputFile) {
    $content = Get-Content $OutputFile
    if ($content) {
        Write-Log "Query Result:" -Level SUCCESS
        $content | ForEach-Object { Write-Log "  $_" -Level SUCCESS }
    } else {
        Write-Log "Output file exists but is EMPTY — query returned no results." -Level WARN
    }
} else {
    Write-Log "Output file not found at '$OutputFile' — task likely failed before writing." -Level ERROR
}

# ============================================================
# STEP 9 - CLEANUP
# ============================================================
Write-Log "------------------------------------------------" -Level SECTION
Write-Log "STEP 9 : Cleanup" -Level SECTION

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
Write-Log "Scheduled task '$TaskName' removed." -Level INFO

if (Test-Path $OutputFile) {
    Remove-Item $OutputFile -Force
    Write-Log "Output file removed." -Level INFO
}

Write-Log "================================================" -Level SECTION
Write-Log " Test Complete. Full log saved to: $LogFile" -Level SECTION
Write-Log "================================================" -Level SECTION

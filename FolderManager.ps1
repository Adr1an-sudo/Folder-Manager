<# =====================================================================
    MANAGE FOLDER PERMISSIONS TOOL

===================================================================== #>

Clear-Host
Write-Host "=== Folder Permission Management Tool ===" -ForegroundColor Cyan

# ============================================================
# Helper: Invoke external exe and capture exit code + output
# ============================================================
function Invoke-ExternalCommand {
    param(
        [Parameter(Mandatory=$true)][string]$FileName,
        [Parameter(Mandatory=$true)][string]$Arguments,
        [int]$TimeoutSec = 0
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FileName
    $psi.Arguments = $Arguments
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardOutput = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi

    [void]$proc.Start()
    if ($TimeoutSec -gt 0) { [void]$proc.WaitForExit($TimeoutSec * 1000) } else { [void]$proc.WaitForExit() }
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()

    [pscustomobject]@{
        ExitCode = $proc.ExitCode
        StdOut   = $stdout
        StdErr   = $stderr
    }
}

# Convenience wrapper to run a full cmd line
function Exec-Cmd {
    param([Parameter(Mandatory=$true)][string]$CmdLine)
    return (Invoke-ExternalCommand -FileName "cmd.exe" -Arguments "/c $CmdLine")
}

# ============================================================
# Sanitize path
# ============================================================
function Sanitize-PathInput {
    param([string]$Raw)

    if ($null -eq $Raw) { return "" }

    $p = $Raw.Trim()

    if ($p.StartsWith('"') -and $p.EndsWith('"')) { $p = $p.Trim('"') }
    $p = $p -replace '\p{Cf}', ''         # strip invisible control chars
    $p = $p -replace "`u{00A0}", " "      # non-breaking space -> space
    $p = $p.Trim()
    $p = $p -replace '/', '\'
    $p = $p -replace '\\{2,}', '\'
    $p = [Environment]::ExpandEnvironmentVariables($p)

    return $p
}

# ============================================================
# Validate folder
# ============================================================
function Get-ValidFolderPath {
    while ($true) {
        $raw  = Read-Host "Enter FULL folder path"
        $path = Sanitize-PathInput -Raw $raw

        if ([string]::IsNullOrWhiteSpace($path)) {
            Write-Host "[!] Path cannot be empty." -ForegroundColor Red
            continue
        }

        if (-not (Test-Path -LiteralPath $path)) {
            Write-Host "[!] Invalid or inaccessible path. Try again." -ForegroundColor Red
            continue
        }

        return $path
    }
}

# ============================================================
# HELP SCREEN (with Deep Restore details + full command)
# ============================================================
function Show-Help {
    Clear-Host
    Write-Host "=== HELP ===" -ForegroundColor Yellow

    Write-Host @"
1) Backup Permissions (ACL+Owner)
   - Saves owner and full ACL to: <folder>.acl.backup (default) or a custom file you choose.

2) Restore Permissions
   - Restores owner/ACL from a chosen backup file created by this tool.

3) Take Ownership
   - Sets owner via icacls (fallback to takeown if needed).
   - Options: Administrators, SYSTEM, TrustedInstaller, Current User, Custom.
   - Optional recursion.

4) Grant FULL CONTROL
   - Grants (F) via icacls to Local Administrators, Domain Admins, Current User, or Custom.
   - Optional recursion.

5) Reset Permissions (icacls)
   - Runs: icacls "<folder>" /reset /T

6) Deep Restore (fix hard lock — run as SYSTEM)
   - Sequence:
     1) takeown /f "<folder>" /r /d y
     2) icacls "<folder>" /grant "BUILTIN\Administrators":(F) /t
     3) icacls "<folder>" /remove:d Everyone /t
     4) icacls "<folder>" /reset /t
     5) icacls "<folder>" /inheritance:e /t
   - If icacls fails, a .NET hard-reset is attempted (owner + FullControl + re-enable inheritance).

To run as SYSTEM (recommended for Deep Restore):
psexec.exe -accepteula -s -h powershell.exe -ExecutionPolicy Bypass -File "<PATH>\Manage-FolderPerms.ps1"
"@

    Read-Host "Press ENTER to return"
}

# ============================================================
# TAKE OWNERSHIP (robust)
# ============================================================
function Take-Ownership {
    param([string]$Folder)

    Write-Host "Select owner:"
    Write-Host "1) Administrators"
    Write-Host "2) SYSTEM"
    Write-Host "3) TrustedInstaller"
    Write-Host "4) Current User"
    Write-Host "5) Custom"
    $choice = Read-Host "Choose (1-5)"

    switch ($choice) {
        "1" { $owner = "BUILTIN\Administrators" }
        "2" { $owner = "NT AUTHORITY\SYSTEM" }
        "3" { $owner = "NT SERVICE\TrustedInstaller" }
        "4" { $owner = "$env:USERDOMAIN\$env:USERNAME" }
        "5" { $owner = Read-Host "Enter identity" }
        default {
            Write-Host "[!] Invalid option." -ForegroundColor Red
            return
        }
    }

    $cascade = Read-Host "Cascade to all subfolders? (y/n)"
    if ($cascade -eq "y") { $recurseSwitch = "/T" } else { $recurseSwitch = "" }

    Write-Host "Setting owner to '$owner'..."

    # First attempt: icacls
    $args = '"{0}" /setowner "{1}" {2}' -f $Folder, $owner, $recurseSwitch
    $res  = Invoke-ExternalCommand -FileName "icacls.exe" -Arguments $args

    if ($res.ExitCode -eq 0) {
        Write-Host "[✔] Ownership updated." -ForegroundColor Green
        return
    }

    Write-Host "[!] icacls failed (exit $($res.ExitCode)). Trying takeown..." -ForegroundColor Yellow

    # Second attempt: takeown + icacls setowner (again)
    $toRes = Exec-Cmd ('takeown /f "{0}" /r /d y' -f $Folder)
    if ($toRes.ExitCode -eq 0) {
        $res2 = Invoke-ExternalCommand -FileName "icacls.exe" -Arguments $args
        if ($res2.ExitCode -eq 0) {
            Write-Host "[✔] Ownership updated (after takeown)." -ForegroundColor Green
            return
        }
    }

    Write-Host "[✖] Failed to update owner. Details:" -ForegroundColor Red
    if ($res.StdErr)  { Write-Host $res.StdErr -ForegroundColor DarkRed }
    if ($toRes -and $toRes.StdErr) { Write-Host $toRes.StdErr -ForegroundColor DarkRed }
}

# ============================================================
# BACKUP (asks where to save)
# ============================================================
function Backup-Permissions {
    param([string]$Folder)

    $default = "$Folder.acl.backup"
    Write-Host "Default backup file: $default"
    $file = Read-Host "Enter FULL PATH to save backup (press ENTER to use default)"

    if ([string]::IsNullOrWhiteSpace($file)) {
        $file = $default
    } else {
        $file = Sanitize-PathInput -Raw $file
    }

    Write-Host "Saving ACL + owner to: $file" -ForegroundColor Yellow
    try {
        $acl = Get-Acl -LiteralPath $Folder
        $acl | Export-Clixml -Path $file
        Write-Host "[✔] Backup complete." -ForegroundColor Green
    } catch {
        Write-Host "[✖] Backup failed: $_" -ForegroundColor Red
    }
}

# ============================================================
# RESTORE (asks for backup file)
# ============================================================
function Restore-Permissions {
    param([string]$Folder)

    $default = "$Folder.acl.backup"
    Write-Host "Default backup file: $default"
    $file = Read-Host "Enter FULL PATH of backup file to restore (press ENTER to use default)"

    if ([string]::IsNullOrWhiteSpace($file)) {
        $file = $default
    } else {
        $file = Sanitize-PathInput -Raw $file
    }

    if (-not (Test-Path -LiteralPath $file)) {
        Write-Host "[!] Backup file not found: $file" -ForegroundColor Red
        return
    }

    try {
        $acl = Import-Clixml -Path $file
        Set-Acl -LiteralPath $Folder -AclObject $acl
        Write-Host "[✔] Permissions restored." -ForegroundColor Green
    } catch {
        Write-Host "[✖] Restore failed: $_" -ForegroundColor Red
    }
}

# ============================================================
# GRANT FULL CONTROL (robust)
# ============================================================
function Grant-FullControl {
    param([string]$Folder)

    Write-Host "Select identity to grant FULL CONTROL (F):"
    Write-Host "1) Local Administrators"
    Write-Host "2) Domain Admins"
    Write-Host "3) Current User"
    Write-Host "4) Custom identity"
    $choice = Read-Host "Choose (1-4)"

    switch ($choice) {
        "1" { $principal = "BUILTIN\Administrators" }
        "2" { $principal = "$env:USERDOMAIN\Domain Admins" }
        "3" { $principal = "$env:USERDOMAIN\$env:USERNAME" }
        "4" { $principal = Read-Host "Enter identity (domain\\user, .\\localuser, SID, or well-known name)" }
        default {
            Write-Host "[!] Invalid option." -ForegroundColor Red
            return
        }
    }

    $cascade = Read-Host "Cascade to all subfolders? (y/n)"
    if ($cascade -eq "y") { $recurseSwitch = "/T" } else { $recurseSwitch = "" }

    Write-Host "Granting FULL CONTROL to '$principal'..."
    # Use ${principal}:(F) so PS doesn't misinterpret the colon
    $args = '"{0}" /grant "{1}":(F) {2}' -f $Folder, $principal, $recurseSwitch
    # invoke icacls
    $res  = Invoke-ExternalCommand -FileName "icacls.exe" -Arguments $args

    if ($res.ExitCode -eq 0) {
        Write-Host "[✔] Full Control granted." -ForegroundColor Green
    } else {
        Write-Host "[✖] Grant failed (exit $($res.ExitCode))." -ForegroundColor Red
        if ($res.StdErr) { Write-Host $res.StdErr -ForegroundColor DarkRed }
    }
}

# ============================================================
# RESET PERMISSIONS (icacls)
# ============================================================
function Reset-Permissions {
    param([string]$Folder)

    Write-Host "Resetting to inherited defaults..."
    $args = '"{0}" /reset /T' -f $Folder
    $res  = Invoke-ExternalCommand -FileName "icacls.exe" -Arguments $args

    if ($res.ExitCode -eq 0) {
        Write-Host "[✔] Permissions reset." -ForegroundColor Green
    } else {
        Write-Host "[✖] Reset failed (exit $($res.ExitCode))." -ForegroundColor Red
        if ($res.StdErr) { Write-Host $res.StdErr -ForegroundColor DarkRed }
    }
}

# ============================================================
# HARD RESET (DirectorySecurity) — bypass DENY if icacls is blocked
# ============================================================
function Hard-ResetAcl {
    param([string]$Folder)

    Write-Host "Performing .NET ACL hard reset..." -ForegroundColor Yellow
    try {
        $admins = New-Object System.Security.Principal.NTAccount('BUILTIN','Administrators')

        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetOwner($admins)

        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule `
            ($admins,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        [void]$acl.SetAccessRule($rule)

        Set-Acl -LiteralPath $Folder -AclObject $acl

        # Re-enable inheritance and reset children using icacls (best-effort)
        Exec-Cmd ('icacls "{0}" /inheritance:e /t' -f $Folder) | Out-Null
        Exec-Cmd ('icacls "{0}" /reset /t' -f $Folder) | Out-Null

        Write-Host "[✔] .NET hard reset complete." -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[✖] .NET hard reset failed: $_" -ForegroundColor Red
        return $false
    }
}

# ============================================================
# Deep Restore (end-to-end repair; assumes SYSTEM context)
# ============================================================
function Deep-Restore {
    param([string]$Folder)

    Write-Host "=== Deep Restore starting ===" -ForegroundColor Cyan

    # 0) Ensure parent is sane (inheritance enabled, Admins have F)
    $parent = Split-Path -Parent $Folder
    if ($parent) {
        Write-Host "Ensuring parent '$parent' has inheritance enabled..." -ForegroundColor Yellow
        Exec-Cmd ('icacls "{0}" /inheritance:e' -f $parent) | Out-Null
        Exec-Cmd ('icacls "{0}" /grant "BUILTIN\Administrators":(F)' -f $parent) | Out-Null
    }

    # 1) takeown → 2) grant Admins → 3) remove DENY Everyone → 4) reset → 5) enable inheritance
    $steps = @(
        'takeown /f "{0}" /r /d y',
        'icacls "{0}" /grant "BUILTIN\Administrators":(F) /t',
        'icacls "{0}" /remove:d Everyone /t',
        'icacls "{0}" /reset /t',
        'icacls "{0}" /inheritance:e /t'
    )

    $allOk = $true
    foreach ($s in $steps) {
        $cmd = ($s -f $Folder)
        Write-Host "Running: $cmd" -ForegroundColor DarkCyan
        $r = Exec-Cmd $cmd
        if ($r.ExitCode -ne 0) {
            Write-Host ("[!] Step failed: {0}" -f $cmd) -ForegroundColor Yellow
            if ($r.StdErr) { Write-Host $r.StdErr -ForegroundColor DarkYellow }
            $allOk = $false
            break
        }
    }

    if (-not $allOk) {
        Write-Host "[i] Trying .NET hard reset path..." -ForegroundColor Yellow
        if (Hard-ResetAcl -Folder $Folder) {
            Write-Host "[✔] Deep Restore completed via .NET hard reset." -ForegroundColor Green
        } else {
            Write-Host "[✖] Deep Restore could not repair the ACL." -ForegroundColor Red
        }
    } else {
        Write-Host "[✔] Deep Restore applied." -ForegroundColor Green
    }
}

# ============================================================
# MAIN LOOP
# ============================================================
$Folder = Get-ValidFolderPath

while ($true) {
    Clear-Host
    Write-Host "=== Folder Permission Management ===" -ForegroundColor Cyan
    Write-Host "Current folder: $Folder" -ForegroundColor Yellow

    Write-Host ""
    Write-Host "1) Backup permissions"
    Write-Host "2) Restore permissions"
    Write-Host "3) Take ownership"
    Write-Host "4) Grant FULL CONTROL"
    Write-Host "5) Reset permissions"
    Write-Host "6) Deep Restore (fix hard lock — run as SYSTEM)"
    Write-Host "H) Help"
    Write-Host "C) Change folder"
    Write-Host "E) Exit"
    Write-Host ""

    $option = Read-Host "Select option"

    switch ($option) {
        "1" { Backup-Permissions -Folder $Folder }
        "2" { Restore-Permissions -Folder $Folder }
        "3" { Take-Ownership     -Folder $Folder }
        "4" { Grant-FullControl  -Folder $Folder }
        "5" { Reset-Permissions  -Folder $Folder }
        "6" { Deep-Restore       -Folder $Folder }
        "H" { Show-Help }
        "C" { $Folder = Get-ValidFolderPath }
        "E" { break }
        default { Write-Host "[!] Invalid option." -ForegroundColor Red }
    }

    Read-Host "Press ENTER to continue"
}

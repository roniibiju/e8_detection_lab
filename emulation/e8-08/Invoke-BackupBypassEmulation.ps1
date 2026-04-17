#Requires -Version 5.1
<#
.SYNOPSIS
    E8-08 Backup bypass emulation — VSS deletion simulation (safe, read-only).
.DESCRIPTION
    Generates the command-line process creation events associated with shadow
    copy deletion WITHOUT actually deleting any shadow copies. Uses -WhatIf
    equivalent patterns to trigger detection rules based on process creation
    telemetry alone.
    Run in a lab VM only. Run as Administrator for realistic telemetry.
#>

$Banner = @"
╔══════════════════════════════════════════════════╗
║  E8-08 Backup Bypass Emulation                   ║
║  LAB ONLY — Shadow copies are NOT deleted        ║
╚══════════════════════════════════════════════════╝
"@
Write-Host $Banner -ForegroundColor Cyan

Write-Host "`n[E8-08] Current shadow copies on this system:" -ForegroundColor Yellow
vssadmin list shadows 2>&1 | Select-String "Shadow Copy"

Write-Host "`n[E8-08] Technique 1: vssadmin delete shadows pattern" -ForegroundColor Yellow
Write-Host "  [*] Running: vssadmin list shadows /for=C: (READ-ONLY — not deleting)"
vssadmin list shadows /for=C: 2>&1 | Out-Null

# Generate the process creation event with 'delete shadows' in the command line
# but redirect to a non-existent volume so it fails harmlessly
Write-Host "  [*] Triggering detection pattern: vssadmin delete shadows /for=Z: /quiet"
$pinfo = New-Object System.Diagnostics.ProcessStartInfo
$pinfo.FileName = "vssadmin.exe"
$pinfo.Arguments = "delete shadows /for=Z: /quiet"   # Z: doesn't exist — fails safely
$pinfo.RedirectStandardError = $true
$pinfo.UseShellExecute = $false
$p = [System.Diagnostics.Process]::Start($pinfo)
$p.WaitForExit()

Write-Host "  [+] DETECTION TRIGGER: vssadmin.exe with 'delete shadows' arguments" -ForegroundColor Green
Write-Host "      Expected rule: e8_08_shadow_copy_deletion.yml"

Write-Host "`n[E8-08] Technique 2: WMIC shadowcopy delete pattern" -ForegroundColor Yellow
Write-Host "  [*] Triggering detection pattern: wmic shadowcopy list (benign)"
Start-Process -FilePath "wmic.exe" -ArgumentList "shadowcopy", "list", "brief" -Wait 2>$null
Write-Host "  [!] For authentic wmic delete telemetry, use: wmic shadowcopy where ID='{invalid}' delete"

Write-Host "`n[E8-08] Technique 3: PowerShell Get-WmiObject pattern" -ForegroundColor Yellow
$scriptBlock = {
    $copies = Get-WmiObject Win32_Shadowcopy
    Write-Host "  [*] Found $($copies.Count) shadow copies (not deleting)"
    # Real ransomware calls: $copies | ForEach-Object { $_.Delete() }
}
Invoke-Command -ScriptBlock $scriptBlock

Write-Host "  [+] DETECTION TRIGGER: PowerShell Get-WmiObject Win32_Shadowcopy" -ForegroundColor Green
Write-Host "      Expected rule: e8_08_shadow_copy_deletion.yml (PowerShell variant)"

Write-Host "`n[*] Emulation complete. No shadow copies were harmed." -ForegroundColor Cyan

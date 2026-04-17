#Requires -Version 5.1
<#
.SYNOPSIS
    E8-03 Office Macro bypass emulation (safe, no real document).
.DESCRIPTION
    Simulates the process-spawn behaviour of a malicious Office macro without
    requiring a real Office document or macro-enabled file. Spawns benign
    child processes from a renamed parent to match the log source pattern.
    Run in a lab VM only.
#>
[CmdletBinding()]
param(
    [ValidateSet('SpawnShell','WriteExe','All')]
    [string]$Technique = 'All'
)

$Banner = @"
╔══════════════════════════════════════════════════╗
║  E8-03 Office Macro Emulation                    ║
║  LAB USE ONLY — No real macro or document        ║
╚══════════════════════════════════════════════════╝
"@
Write-Host $Banner -ForegroundColor Cyan

function Test-OfficeSpawnsShell {
    Write-Host "`n[E8-03] Technique: Office process spawns cmd.exe" -ForegroundColor Yellow

    # Stage a renamed copy of cmd.exe as "WINWORD.EXE" in temp to fake the parent
    # In a real lab, just open a macro-enabled document and click Enable Content
    $fakeWordPath = Join-Path $env:TEMP "WINWORD.EXE"
    Copy-Item "$env:SystemRoot\System32\cmd.exe" $fakeWordPath -Force

    Write-Host "  [*] Simulating WINWORD.EXE spawning cmd.exe /c whoami"
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $fakeWordPath
    $pinfo.Arguments = "/c whoami"
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $p = [System.Diagnostics.Process]::Start($pinfo)
    $p.WaitForExit()

    Write-Host "  [+] DETECTION TRIGGER: WINWORD.EXE (temp) spawned cmd.exe" -ForegroundColor Green
    Write-Host "      Expected rule: e8_03_office_spawns_shell_process.yml"
    Write-Host "  [!] NOTE: For authentic telemetry open a macro-enabled doc in a real Office install"

    Remove-Item $fakeWordPath -Force -ErrorAction SilentlyContinue
}

function Test-OfficeWritesExe {
    Write-Host "`n[E8-03] Technique: Office process writes .exe to disk" -ForegroundColor Yellow

    $fakeWordPath = Join-Path $env:TEMP "EXCEL.EXE"
    Copy-Item "$env:SystemRoot\System32\cmd.exe" $fakeWordPath -Force

    $droppedExe = Join-Path $env:TEMP "e8_dropped_payload.exe"

    Write-Host "  [*] Simulating EXCEL.EXE writing an executable to temp"
    Copy-Item "$env:SystemRoot\System32\whoami.exe" $droppedExe -Force

    Write-Host "  [+] DETECTION TRIGGER: File create event — .exe written by EXCEL.EXE (temp)" -ForegroundColor Green
    Write-Host "      Expected rule: e8_03_office_writes_executable_to_disk.yml"
    Write-Host "      Requires: Sysmon EventID 11 or EDR file telemetry"

    Remove-Item $fakeWordPath,$droppedExe -Force -ErrorAction SilentlyContinue
}

switch ($Technique) {
    'SpawnShell' { Test-OfficeSpawnsShell }
    'WriteExe'   { Test-OfficeWritesExe }
    'All' {
        Test-OfficeSpawnsShell
        Test-OfficeWritesExe
    }
}

Write-Host "`n[*] Emulation complete." -ForegroundColor Cyan
Write-Host "    For authentic results: use a real Office install with a macro-enabled XLSM/DOCM"

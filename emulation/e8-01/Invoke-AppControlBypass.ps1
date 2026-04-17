#Requires -Version 5.1
<#
.SYNOPSIS
    E8-01 Application Control bypass emulation (safe, no payload).
.DESCRIPTION
    Simulates techniques used to bypass AppLocker/WDAC by executing a benign
    command from a user-writable path and via LOLBAS (mshta, regsvr32).
    Run in a lab VM only. Does NOT download or execute real payloads.
.PARAMETER Technique
    Which bypass to emulate: WritablePath, LOLBAS_Mshta, LOLBAS_Regsvr32
.EXAMPLE
    .\Invoke-AppControlBypass.ps1 -Technique WritablePath
    .\Invoke-AppControlBypass.ps1 -Technique LOLBAS_Mshta
#>
[CmdletBinding()]
param(
    [ValidateSet('WritablePath','LOLBAS_Mshta','LOLBAS_Regsvr32','All')]
    [string]$Technique = 'All'
)

$Banner = @"
╔══════════════════════════════════════════════════╗
║  E8-01 Application Control Bypass Emulation      ║
║  LAB USE ONLY — No real payload executed         ║
╚══════════════════════════════════════════════════╝
"@
Write-Host $Banner -ForegroundColor Cyan

function Test-WritablePath {
    Write-Host "`n[E8-01] Technique: Execution from user-writable path" -ForegroundColor Yellow
    $tempExe = Join-Path $env:TEMP "e8_emulation_test.exe"

    # Copy a harmless signed binary to temp to simulate staging a payload
    Copy-Item -Path "$env:SystemRoot\System32\whoami.exe" -Destination $tempExe -Force
    Write-Host "  [*] Staged binary: $tempExe"

    Write-Host "  [*] Executing from temp path..."
    & $tempExe | Out-Null

    Write-Host "  [+] DETECTION TRIGGER: Process creation from $tempExe" -ForegroundColor Green
    Write-Host "      Expected rule: e8_01_execution_from_user_writable_path.yml"

    Remove-Item $tempExe -Force -ErrorAction SilentlyContinue
    Write-Host "  [*] Cleaned up"
}

function Test-LolbasMshta {
    Write-Host "`n[E8-01] Technique: LOLBAS - mshta.exe proxy execution" -ForegroundColor Yellow

    # Write a benign HTA that only shows a message box — no network, no payload
    $htaContent = @"
<html><head><script language="VBScript">
MsgBox "E8 Detection Lab: mshta emulation - benign", 64, "E8-01 Emulation"
window.close()
</script></head></html>
"@
    $htaPath = Join-Path $env:TEMP "e8_emulation.hta"
    Set-Content -Path $htaPath -Value $htaContent -Encoding UTF8

    Write-Host "  [*] Launching mshta.exe with local HTA..."
    Start-Process -FilePath "mshta.exe" -ArgumentList $htaPath -Wait

    Write-Host "  [+] DETECTION TRIGGER: mshta.exe execution" -ForegroundColor Green
    Write-Host "      Expected rule: e8_01_lolbas_application_control_bypass.yml"

    Remove-Item $htaPath -Force -ErrorAction SilentlyContinue
}

function Test-LolbasRegsvr32 {
    Write-Host "`n[E8-01] Technique: LOLBAS - regsvr32.exe Squiblydoo" -ForegroundColor Yellow
    Write-Host "  [*] Simulating regsvr32 /s /i command-line pattern (no network call)"

    # Run regsvr32 against a benign local DLL to generate the process creation event
    $cmd = "regsvr32.exe /s /i:C:\Windows\System32\scrrun.dll scrobj.dll"
    Write-Host "  [*] Command: $cmd"
    Start-Process -FilePath "regsvr32.exe" -ArgumentList "/s", "/i:C:\Windows\System32\scrrun.dll", "scrobj.dll" -Wait 2>$null

    Write-Host "  [+] DETECTION TRIGGER: regsvr32 with /s /i scrobj.dll arguments" -ForegroundColor Green
    Write-Host "      Expected rule: e8_01_lolbas_application_control_bypass.yml"
}

switch ($Technique) {
    'WritablePath'    { Test-WritablePath }
    'LOLBAS_Mshta'    { Test-LolbasMshta }
    'LOLBAS_Regsvr32' { Test-LolbasRegsvr32 }
    'All' {
        Test-WritablePath
        Test-LolbasMshta
        Test-LolbasRegsvr32
    }
}

Write-Host "`n[*] Emulation complete. Check your SIEM for triggered detections." -ForegroundColor Cyan

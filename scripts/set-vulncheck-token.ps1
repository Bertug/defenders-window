# Prompts for a VulnCheck API token without echoing it and stores it encrypted
# for the current Windows user (DPAPI). Use this to rotate the token.
$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:APPDATA 'ExploitationObservatory'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$secure = Read-Host 'VulnCheck API token' -AsSecureString
if ($secure.Length -eq 0) { throw 'No token entered.' }
$secure | Export-Clixml -LiteralPath (Join-Path $dir 'vulncheck-token.clixml')
Write-Host 'Stored encrypted for this Windows user.'

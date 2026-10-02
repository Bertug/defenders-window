# Loads the DPAPI-encrypted VulnCheck token into this process only, runs a Node
# script, then clears it. The token is never written to disk in plaintext.
param([Parameter(Mandatory)][string]$Script, [string[]]$Arguments = @())
$ErrorActionPreference = 'Stop'
$path = Join-Path $env:APPDATA 'ExploitationObservatory\vulncheck-token.clixml'
if (-not (Test-Path -LiteralPath $path)) { throw "No stored VulnCheck token. Run scripts\set-vulncheck-token.ps1 first." }
$secure = Import-Clixml -LiteralPath $path
$env:VULNCHECK_API_TOKEN = [System.Net.NetworkCredential]::new('', $secure).Password
try {
  & node $Script @Arguments
  if ($LASTEXITCODE) { exit $LASTEXITCODE }
} finally {
  Remove-Item Env:VULNCHECK_API_TOKEN -ErrorAction SilentlyContinue
}

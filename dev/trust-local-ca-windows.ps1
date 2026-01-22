$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ca = Join-Path $root "dev\certs\local-ca.crt"

if (!(Test-Path $ca)) {
  Write-Host "Missing CA cert: $ca"
  Write-Host "Generate it first (WSL/Git Bash):"
  Write-Host "  bash dev/generate-local-certs.sh"
  exit 1
}

Write-Host "==> Trust local CA in Windows Trusted Root (requires Administrator)"
Write-Host "CA: $ca"

# certutil is available on Windows. This installs into LocalMachine\Root.
certutil.exe -addstore -f Root $ca | Out-Host

Write-Host ""
Write-Host "Done."
Write-Host "- Restart Chrome/Chromium completely."
Write-Host "- Then open: https://dpop.skplanet.com:8443/"


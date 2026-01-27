param(
    [string]$Python = "python"
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..")

& $Python -m pip install -r (Join-Path $repoRoot "requirements-online.txt")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Online install complete. Note: usb_tool is excluded and must be installed separately."

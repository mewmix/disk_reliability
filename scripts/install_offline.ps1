param(
    [string]$Python = "python"
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..")
$wheelDir = Join-Path $repoRoot "wheels"

& $Python -m pip install --no-index --find-links $wheelDir -r (Join-Path $repoRoot "requirements-offline.txt")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Offline install complete."

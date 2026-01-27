param(
    [string]$Python = "python",
    [string]$UsbToolWheel = ""
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..")
$wheelDir = Join-Path $repoRoot "wheels"

New-Item -ItemType Directory -Force -Path $wheelDir | Out-Null

& $Python -m pip download -r (Join-Path $repoRoot "requirements-online.txt") -d $wheelDir
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($UsbToolWheel -ne "") {
    Copy-Item -Path $UsbToolWheel -Destination $wheelDir -Force
    Write-Host "Copied usb_tool wheel to $wheelDir"
} else {
    Write-Host "usb_tool wheel not provided; offline installs will require it to be present in $wheelDir"
}

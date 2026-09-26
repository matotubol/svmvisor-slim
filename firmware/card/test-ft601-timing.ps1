[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$config = Import-PowerShellDataFile (Join-Path $PSScriptRoot 'config.psd1')
$outputPath = Join-Path $workspaceRoot ('target/firmware/card/ft601-timing/' + [Guid]::NewGuid().ToString('N'))
$snapshotPath = Join-Path $outputPath 'source'
$sourceFiles = @(
    'rtl/ft601_transport_phy.sv',
    'rtl/ft601_transport_clock.sv',
    'rtl/tb/ft601_transport_bench.sv',
    'rtl/tb/ft601_transport_bench.xdc',
    'vivado/ft601-transport.tcl'
)
$manifest = foreach ($relativePath in $sourceFiles) {
    $sourcePath = Join-Path $PSScriptRoot $relativePath
    $destinationPath = Join-Path $snapshotPath $relativePath
    New-Item -ItemType Directory -Path (Split-Path $destinationPath) -Force | Out-Null
    Copy-Item -LiteralPath $sourcePath -Destination $destinationPath
    [ordered]@{path=$relativePath; sha256=(Get-FileHash -LiteralPath $destinationPath -Algorithm SHA256).Hash.ToLowerInvariant()}
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $outputPath 'sources.json') -Encoding utf8
Write-Host "Standalone FT601 timing evidence: $outputPath"
Push-Location $outputPath
try {
    & (Join-Path $config.VivadoRoot 'Vivado/bin/vivado.bat') -mode batch -source (Join-Path $snapshotPath 'vivado/ft601-transport.tcl') -tclargs $snapshotPath $outputPath
    if ($LASTEXITCODE -ne 0) {throw "Standalone FT601 timing failed; evidence: $outputPath"}
} finally {Pop-Location}
Write-Host "Standalone FT601 timing passed: $outputPath"

[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$config = Import-PowerShellDataFile (Join-Path $PSScriptRoot 'config.psd1')
$bin = Join-Path $config.VivadoRoot 'Vivado/bin'
$outputPath = Join-Path $workspaceRoot ('target/firmware/card/ft601-sim/' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
$sources = @('rtl/ft601_transport_phy.sv', 'rtl/tb/ft601_transport_phy_tb.sv')
$manifest = foreach ($relativePath in $sources) {
    $destinationPath = Join-Path $outputPath (Split-Path $relativePath -Leaf)
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $relativePath) -Destination $destinationPath
    [ordered]@{path=$relativePath; sha256=(Get-FileHash -LiteralPath $destinationPath -Algorithm SHA256).Hash.ToLowerInvariant()}
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $outputPath 'sources.json') -Encoding utf8
Push-Location $outputPath
try {
    & (Join-Path $bin 'xvlog.bat') -sv ft601_transport_phy.sv ft601_transport_phy_tb.sv
    if ($LASTEXITCODE -ne 0) {throw 'FT601 transport RTL compile failed.'}
    & (Join-Path $bin 'xelab.bat') ft601_transport_phy_tb -s ft601_transport_phy_tb
    if ($LASTEXITCODE -ne 0) {throw 'FT601 transport elaboration failed.'}
    $simulationOutput = & (Join-Path $bin 'xsim.bat') ft601_transport_phy_tb -runall 2>&1
    $simulationExitCode = $LASTEXITCODE
    $simulationOutput | Set-Content -LiteralPath 'simulation.log' -Encoding utf8
    $simulationOutput | Write-Host
    if ($simulationExitCode -ne 0 -or ($simulationOutput -join "`n") -notmatch 'PASS:' -or ($simulationOutput -join "`n") -match '(?i)(Fatal:|Error:)') {
        throw "FT601 transport simulation failed; evidence: $outputPath"
    }
} finally {Pop-Location}
Write-Host "FT601 transport simulation passed: $outputPath"

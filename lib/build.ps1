# ============================================================================
#  Rebuild coding/lib: compile the MPC4J SEAL module and refresh the deps.
#  (ASCII only: Windows PowerShell 5.1 reads .ps1 as ANSI/GBK without a BOM)
#
#  Usage:  .\build.ps1
# ============================================================================
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Definition
$root = Split-Path -Parent (Split-Path -Parent $here)   # workspace root

$javacPath = (Get-Command javac -ErrorAction SilentlyContinue).Source
if (-not $javacPath) { $javacPath = 'D:\Java\jdk\bin\javac.exe' }
$jarPath = Join-Path (Split-Path -Parent $javacPath) 'jar.exe'

# ---- 1. deps ----
$deps = Join-Path $here 'deps'
New-Item -ItemType Directory -Force -Path $deps | Out-Null
$cpFile = Join-Path $root 'cape_test\cp.txt'
if (Test-Path $cpFile) {
    $jars = (Get-Content $cpFile -Raw).Trim() -split ';'
    $n = 0
    foreach ($j in $jars) {
        if (Test-Path $j) { Copy-Item $j $deps -Force; $n++ }
        else { Write-Warning "missing dependency: $j" }
    }
    Write-Host "[deps] copied $n jar(s)"
} else {
    Write-Warning "cape_test\cp.txt not found; keep the existing deps\ folder (see deps\VERSIONS.md)"
}

# ---- 2. compile the SEAL module ----
$sealSrc = Join-Path $root 'mpc4j\mpc4j-crypto-fhe\mpc4j-crypto-fhe-seal\src\main\java'
if (-not (Test-Path $sealSrc)) {
    Write-Error "MPC4J source not found at $sealSrc (clone alibaba-edu/mpc4j first)"
    exit 1
}
$classes = Join-Path $here 'build\classes'
if (Test-Path (Join-Path $here 'build')) { Remove-Item -Recurse -Force (Join-Path $here 'build') }
New-Item -ItemType Directory -Force -Path $classes | Out-Null

$depsCp = (Get-ChildItem $deps -Filter *.jar | ForEach-Object { $_.FullName }) -join ';'
$src = Get-ChildItem $sealSrc -Recurse -Filter *.java | ForEach-Object { $_.FullName }
Write-Host "[compile] $($src.Count) source files"
& $javacPath -encoding UTF-8 -nowarn -cp $depsCp -d $classes $src
if ($LASTEXITCODE -ne 0) { Write-Error 'compile failed'; exit $LASTEXITCODE }

$jar = Join-Path $here 'mpc4j-crypto-fhe-seal.jar'
& $jarPath cf $jar -C $classes .
Remove-Item -Recurse -Force (Join-Path $here 'build')
Write-Host "[jar] $jar"

# ---- 3. license ----
$lic = Join-Path $root 'mpc4j\LICENSE'
if (Test-Path $lic) { Copy-Item $lic (Join-Path $here 'MPC4J-LICENSE') -Force; Write-Host '[license] MPC4J-LICENSE refreshed' }
Write-Host '[done]'
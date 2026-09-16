# ============================================================================
#  RLWE efficiency benchmark: this implementation vs MPC4J
#  (ASCII only: Windows PowerShell 5.1 reads .ps1 as ANSI/GBK without a BOM)
#
#  Usage:  .\run.ps1
# ============================================================================
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Definition
$coding = Split-Path -Parent $here

$javacPath = (Get-Command javac -ErrorAction SilentlyContinue).Source
if (-not $javacPath) { $javacPath = 'D:\Java\jdk\bin\javac.exe' }
$javaPath = Join-Path (Split-Path -Parent $javacPath) 'java.exe'

# dependencies: rlwe-java (pure JDK) + MPC4J seal classes + its jars
$rlweOut = Join-Path $coding 'rlwe-java\out'
if (-not (Test-Path $rlweOut)) {
    Write-Host "[prep] building rlwe-java first"
    Push-Location (Join-Path $coding 'rlwe-java'); & .\run.ps1 jar | Out-Null; Pop-Location
}
$mpc4jClasses = Join-Path (Split-Path -Parent $coding) 'cape_test\classes'
$cpFile = Join-Path (Split-Path -Parent $coding) 'cape_test\cp.txt'
if (-not (Test-Path $mpc4jClasses)) {
    Write-Error "MPC4J classes not found at $mpc4jClasses (build cape_test first)"
    exit 1
}
$jars = if (Test-Path $cpFile) { (Get-Content $cpFile -Raw).Trim() } else { '' }
$cp = "$rlweOut;$mpc4jClasses;$jars"

$out = Join-Path $here 'out'
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory -Force -Path $out | Out-Null

Write-Host "[compile] RlweBench.java"
& $javacPath -encoding UTF-8 -cp $cp -d $out (Join-Path $here 'src\RlweBench.java')
if ($LASTEXITCODE -ne 0) { Write-Error 'compile failed'; exit $LASTEXITCODE }

Write-Host "[run] RlweBench"
& $javaPath '-Xmx4g' '-Dfile.encoding=UTF-8' -cp "$out;$cp" RlweBench
exit $LASTEXITCODE

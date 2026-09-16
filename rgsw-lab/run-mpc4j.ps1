# ============================================================================
#  Run the RGSW-on-MPC4J self-test using coding/lib (no external paths).
#  (ASCII only: Windows PowerShell 5.1 reads .ps1 as ANSI/GBK without a BOM)
#
#  Usage:  .\run-mpc4j.ps1
# ============================================================================
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Definition
$lib  = Join-Path (Split-Path -Parent $here) 'lib'
$javacPath = (Get-Command javac -ErrorAction SilentlyContinue).Source
if (-not $javacPath) { $javacPath = 'D:\Java\jdk\bin\javac.exe' }
$javaPath = Join-Path (Split-Path -Parent $javacPath) 'java.exe'

$cp = (Join-Path $lib 'mpc4j-crypto-fhe-seal.jar') + ';' +
      ((Get-ChildItem (Join-Path $lib 'deps') -Filter *.jar | ForEach-Object { $_.FullName }) -join ';')

$out = Join-Path $here 'mpc4j-out'
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory -Force -Path $out | Out-Null

Write-Host "[compile] Mpc4jRgsw.java (classpath = coding\lib)"
& $javacPath -encoding UTF-8 -cp $cp -d $out (Join-Path $here 'src\main\java\com\fusepir\rgsw\Mpc4jRgsw.java')
if ($LASTEXITCODE -ne 0) { Write-Error 'compile failed'; exit $LASTEXITCODE }

Write-Host "[run] com.fusepir.rgsw.Mpc4jRgsw"
& $javaPath '-Xmx4g' '-Dfile.encoding=UTF-8' -cp "$out;$cp" com.fusepir.rgsw.Mpc4jRgsw
exit $LASTEXITCODE
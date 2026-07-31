$ErrorActionPreference = "Stop"

$env:GHIDRA_INSTALL_DIR = "D:\GotYaForce\ghidra_12.1.2_PUBLIC"
$env:JAVA_HOME = "C:\Program Files\Java\jdk-21.0.10"
$env:Path = "$env:JAVA_HOME\bin;$env:Path"

$ghidraRun = "D:\GotYaForce\ghidra_12.1.2_PUBLIC\ghidraRun.bat"
$ghidraGo = "D:\GotYaForce\ghidra_12.1.2_PUBLIC\support\GhidraGo\ghidraGo.bat"
$project = "D:\GotYaForce\research\decomp\GotchaForce.gpr"
$projectData = "D:\GotYaForce\research\decomp\GotchaForce.rep"
$programProperties = Join-Path $projectData "idata\00\00000000.prp"
$programIndex = Join-Path $projectData "idata\~index.dat"
$programUrl = "ghidra:/D:/GotYaForce/research/decomp/GotchaForce?/boot.dol"
$oghidraBaseUrl = "http://127.0.0.1:8080"

if (!(Test-Path -LiteralPath $ghidraRun)) {
  throw "Ghidra launcher not found at $ghidraRun"
}

if (!(Test-Path -LiteralPath $project)) {
  throw "Ghidra project not found at $project"
}

if (!(Test-Path -LiteralPath $ghidraGo)) {
  throw "GhidraGo launcher not found at $ghidraGo"
}

if (!(Test-Path -LiteralPath $programIndex) -or
    !(Test-Path -LiteralPath $programProperties) -or
    !(Select-String -LiteralPath $programIndex -SimpleMatch "boot.dol" -Quiet)) {
  throw @"
boot.dol is not registered in the active Ghidra project.
Expected catalog files:
  $programIndex
  $programProperties
The analyzed database may still exist, but Ghidra cannot display it without these records.
"@
}

function Get-OGhidraProgram {
  try {
    return Invoke-RestMethod -TimeoutSec 2 -Uri "$oghidraBaseUrl/program"
  }
  catch {
    return $null
  }
}

function Get-OGhidraFirstFunction {
  try {
    return Invoke-RestMethod -TimeoutSec 2 -Uri "$oghidraBaseUrl/list_functions?offset=0&limit=1"
  }
  catch {
    return $null
  }
}

$activeProgram = Get-OGhidraProgram
if ($null -eq $activeProgram) {
  Start-Process -FilePath $ghidraRun -ArgumentList "`"$project`""
  Write-Host "Opening Ghidra project: $project"

  Start-Sleep -Seconds 5
  Start-Process -FilePath $ghidraGo -ArgumentList "`"$programUrl`"" -Wait
  Write-Host "Requested CodeBrowser program: boot.dol"
}

$deadline = (Get-Date).AddSeconds(90)
do {
  $activeProgram = Get-OGhidraProgram
  $firstFunction = Get-OGhidraFirstFunction
  if ($null -ne $activeProgram -and $null -ne $firstFunction -and
      "$firstFunction".Trim().Length -gt 0) {
    Write-Host "OGhidra ready: boot.dol is active and functions are available."
    Write-Host "API: $oghidraBaseUrl"
    exit 0
  }
  Start-Sleep -Seconds 1
} while ((Get-Date) -lt $deadline)

throw @"
Ghidra opened, but OGhidra did not expose an active function within 90 seconds.
Check that these plugins are enabled:
  Project Window: GhidraGoPlugin
  CodeBrowser:    GhidraMCPPlugin
Then open boot.dol and rerun this script.
"@

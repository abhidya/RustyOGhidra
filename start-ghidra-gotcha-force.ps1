$ErrorActionPreference = "Stop"

$env:GHIDRA_INSTALL_DIR = "D:\GotYaForce\ghidra_12.1.2_PUBLIC"
$env:JAVA_HOME = "C:\Program Files\Java\jdk-21.0.10"
$env:Path = "$env:JAVA_HOME\bin;$env:Path"

$ghidraRun = "D:\GotYaForce\ghidra_12.1.2_PUBLIC\ghidraRun.bat"
$project = "D:\GotYaForce\research\decomp\GotchaForce.gpr"

if (!(Test-Path -LiteralPath $ghidraRun)) {
  throw "Ghidra launcher not found at $ghidraRun"
}

if (!(Test-Path -LiteralPath $project)) {
  throw "Ghidra project not found at $project"
}

Start-Process -FilePath $ghidraRun -ArgumentList "`"$project`""

Write-Host "Opened Ghidra project: $project"
Write-Host "Next: open boot.dol in CodeBrowser and enable OGhidraMCP if prompted."

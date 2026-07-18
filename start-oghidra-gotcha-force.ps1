param(
  [switch]$LegacyMode
)

$ErrorActionPreference = "Stop"

$env:GHIDRA_INSTALL_DIR = "D:\GotYaForce\ghidra_12.1.2_PUBLIC"
$env:JAVA_HOME = "C:\Program Files\Java\jdk-21.0.10"
$env:Path = "$env:JAVA_HOME\bin;$env:Path"
$env:AGENTIC_RENAME = "1"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = "D:\GotYaForce\research\tools\OGhidra\.venv\Scripts\python.exe"
$main = Join-Path $scriptDir "main.py"
$renamePrompt = Join-Path $scriptDir "PROMPT-rename-gotcha-functions.md"
$ghidraRun = "D:\GotYaForce\ghidra_12.1.2_PUBLIC\support\pyghidraRun.bat"
$project = "D:\GotYaForce\research\decomp\GotchaForce.gpr"
$ghidraMethodsUrl = "http://127.0.0.1:8080/methods?offset=0&limit=1"

if (!(Test-Path -LiteralPath $python)) {
  throw "OGhidra venv Python not found at $python"
}

if (!(Test-Path -LiteralPath $main)) {
  throw "OGhidra main.py not found at $main"
}

if (!(Test-Path -LiteralPath $project)) {
  throw "Ghidra project not found at $project"
}

if (!(Test-Path -LiteralPath $ghidraRun)) {
  throw "Ghidra launcher not found at $ghidraRun"
}

function Test-GhidraMcp {
  try {
    $response = Invoke-WebRequest -Uri $ghidraMethodsUrl -UseBasicParsing -TimeoutSec 2
    return ($response.StatusCode -eq 200 -and $response.Content.Length -gt 0)
  }
  catch {
    return $false
  }
}

if (!(Test-GhidraMcp)) {
  Write-Host "Starting Ghidra with GotchaForce.gpr..."
  Start-Process -FilePath $ghidraRun -ArgumentList "`"$project`""

  Write-Host ""
  Write-Host "In Ghidra:"
  Write-Host "  1. Open boot.dol in CodeBrowser."
  Write-Host "  2. If prompted, enable OGhidraMCP in File > Configure."
  Write-Host "  3. Wait for this window to continue after http://127.0.0.1:8080/methods responds."
  Write-Host ""

  for ($i = 1; $i -le 180; $i++) {
    if (Test-GhidraMcp) {
      break
    }
    Start-Sleep -Seconds 2
  }
}

if (!(Test-GhidraMcp)) {
  throw "OGhidraMCP is not responding. Open boot.dol in Ghidra CodeBrowser and enable OGhidraMCP, then rerun this script."
}

Write-Host "OGhidraMCP is responding. Launching OGhidra UI with HTTP backend."
Write-Host "Rename prompt: $renamePrompt"

$oghidraArgs = @(
  "--ui",
  "--ghidra-backend=http"
)

if (!$LegacyMode) {
  $oghidraArgs += "--task-mode=port_1to1"
  $oghidraArgs += "--enable-hybrid-search"
  Write-Host "Workflow: evidence-first Gotcha Force 1:1 port mode"
  Write-Host "Scope each query to one Borg family and one action index."
}
else {
  Write-Host "Workflow: legacy/default OGhidra mode"
}

Push-Location $scriptDir
try {
  # CAG is now enabled: the Gotcha Force knowledge base (research notes + borg roster,
  # embedded to data/vector_db) flows into naming via semantic retrieval, and the
  # deterministic resolver (src/gf_context.py) injects exact struct-offset / symbol / borg
  # lookups. Embeddings are served separately at CUSTOM_API_EMBEDDING_URL (:1234).
  & $python $main @oghidraArgs
}
finally {
  Pop-Location
}

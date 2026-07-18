$ErrorActionPreference = "Stop"

$python = "D:\GotYaForce\research\tools\OGhidra\.venv\Scripts\python.exe"
$envFile = "D:\GotYaForce\research\tools\OGhidra\.env.deepai"
$exampleFile = "D:\GotYaForce\research\tools\OGhidra\.env.deepai.example"

if (!(Test-Path -LiteralPath $python)) {
  throw "OGhidra venv Python not found at $python"
}

if (!(Test-Path -LiteralPath $envFile)) {
  Copy-Item -LiteralPath $exampleFile -Destination $envFile
  throw "Created $envFile. Add DEEPAI_API_KEY there, then rerun this script."
}

& $python deepai_openai_adapter.py

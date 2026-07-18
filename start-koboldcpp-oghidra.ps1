$ErrorActionPreference = "Stop"

$kobold = "D:\models\koboldcpp.exe"
$model = "D:\models\Qwen3VL-8B-Instruct-Q4_K_M.gguf"

if (!(Test-Path -LiteralPath $kobold)) {
  throw "koboldcpp.exe not found at $kobold"
}

if (!(Test-Path -LiteralPath $model)) {
  throw "Model not found at $model"
}

# Stable setup for the local 8B Qwen model across two GPUs.
# If koboldcpp reports out-of-memory, lower --gpulayers first, then --contextsize.
& $kobold `
  --model $model `
  --host 127.0.0.1 `
  --port 5001 `
  --contextsize 8192 `
  --usecublas `
  --gpulayers 99 `
  --tensor_split 11,8

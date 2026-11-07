$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$python = Join-Path $repoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Project interpreter not found. Create the project .venv first."
}

$configuredRoot = $env:OMNIPATCH_DEMO_ROOT
$tempRoot = if ([string]::IsNullOrWhiteSpace($configuredRoot)) {
    $env:TEMP
} else {
    $configuredRoot
}
if ([string]::IsNullOrWhiteSpace($tempRoot) -or -not (Test-Path -LiteralPath $tempRoot -PathType Container)) {
    throw "Demo output root must be an existing external directory."
}
$tempRoot = [System.IO.Path]::GetFullPath($tempRoot)
$cursor = [System.IO.DirectoryInfo]::new($tempRoot)
while ($null -ne $cursor) {
    if (Test-Path -LiteralPath (Join-Path $cursor.FullName ".git")) {
        throw "TEMP is inside a Git repository; choose an external TEMP directory."
    }
    $cursor = $cursor.Parent
}

$runRoot = Join-Path $tempRoot ("omnipatch-b608-demo-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $runRoot | Out-Null
$output = Join-Path $runRoot "artifacts"
if (Test-Path -LiteralPath $output) {
    throw "Demo output directory already exists. No files were overwritten."
}

$savedLocation = Get-Location
$names = @(
    "OMNIPATCH_LLM_PROVIDER",
    "OMNIPATCH_LLM_OUTPUT",
    "OMNIPATCH_LLM_MODEL",
    "OMNIPATCH_OLLAMA_ENDPOINT",
    "PYTHONPATH"
)
$previous = @{}
$removedCredentials = @{}
$exitCode = 2
foreach ($name in $names) {
    $previous[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}

try {
    Set-Location -LiteralPath $runRoot
    $env:OMNIPATCH_LLM_PROVIDER = "ollama"
    $env:OMNIPATCH_LLM_OUTPUT = "function"
    $env:OMNIPATCH_LLM_MODEL = "qwen-ctx8k:latest"
    $env:OMNIPATCH_OLLAMA_ENDPOINT = "http://127.0.0.1:11434/api/chat"
    $env:PYTHONPATH = "$repoRoot;$repoRoot\src"

    foreach ($entry in Get-ChildItem Env:) {
        if ($entry.Name -match "(?i)(API_KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|GITHUB|ANTHROPIC)") {
            $removedCredentials[$entry.Name] = $entry.Value
            Remove-Item -LiteralPath "Env:$($entry.Name)"
        }
    }

    & $python -m benchmarks.v1.demo --output-dir $output
    $exitCode = $LASTEXITCODE
}
finally {
    Set-Location -LiteralPath $savedLocation
    foreach ($name in $names) {
        [Environment]::SetEnvironmentVariable($name, $previous[$name], "Process")
    }
    foreach ($name in $removedCredentials.Keys) {
        [Environment]::SetEnvironmentVariable($name, $removedCredentials[$name], "Process")
    }
}
exit $exitCode

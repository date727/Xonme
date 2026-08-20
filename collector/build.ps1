$ErrorActionPreference = "Stop"
$collectorRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$configPath = Join-Path $collectorRoot "config.json"
$requirementsPath = Join-Path $collectorRoot "requirements.txt"
$entryPath = Join-Path $collectorRoot "main.py"
$outputPath = Join-Path $collectorRoot "dist\C2Sherlock-Collector.exe"
$venvPythonPath = Join-Path $collectorRoot ".venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $configPath)) {
    throw "Missing collector/config.json. Copy config.json.example to config.json and configure it before building."
}

if (Test-Path -LiteralPath $venvPythonPath) {
    $pythonPath = $venvPythonPath
} else {
    $pythonPath = (Get-Command python -ErrorAction Stop).Source
    Write-Warning "collector/.venv was not found; using Python from PATH: $pythonPath"
}
Push-Location $collectorRoot
try {
    Write-Host "Using Python: $pythonPath"
    & $pythonPath -m pip install -r $requirementsPath
    if ($LASTEXITCODE -ne 0) {
        throw "Dependency installation failed with exit code $LASTEXITCODE."
    }

    $pyInstallerArguments = @(
        "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--name", "C2Sherlock-Collector",
        "--collect-all", "uvicorn",
        "--add-data", "config.json;.",
        $entryPath
    )
    & $pythonPath @pyInstallerArguments
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller failed with exit code $LASTEXITCODE."
    }
} finally {
    Pop-Location
}

if (-not (Test-Path -LiteralPath $outputPath)) {
    throw "PyInstaller finished without creating the expected executable: $outputPath"
}

Write-Host "Build complete: $outputPath"

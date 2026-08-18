$ErrorActionPreference = "Stop"
$collectorRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $collectorRoot

if (-not (Test-Path -LiteralPath (Join-Path $collectorRoot "config.json"))) {
    throw "请先复制 config.json.example 为 config.json，并填写云端 API 与网页来源。"
}

python -m pip install -r requirements.txt
python -m PyInstaller --noconfirm --clean --onefile --name C2Sherlock-Collector --collect-all uvicorn --add-data "config.json;." main.py

Write-Host "Build complete: $collectorRoot\dist\C2Sherlock-Collector.exe"

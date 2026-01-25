# Update requirements.txt from pyproject.toml
# PowerShell version for Windows

Write-Host "🔄 Regenerating requirements.txt from pyproject.toml..." -ForegroundColor Cyan

# Generate requirements.txt without header
uv pip compile pyproject.toml -o requirements-temp.txt --no-header

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to compile dependencies" -ForegroundColor Red
    exit 1
}

# Create header
$header = @"
# This file is auto-generated from pyproject.toml using 'uv pip compile'
# DO NOT EDIT MANUALLY - Use 'uv add/remove' to manage dependencies
# To regenerate: Run .\scripts\update_requirements.ps1

"@

# Combine header and requirements
$header | Out-File -FilePath requirements.txt -Encoding utf8 -NoNewline
Get-Content requirements-temp.txt | Add-Content -Path requirements.txt -Encoding utf8

# Remove temporary file
Remove-Item requirements-temp.txt

# Count packages
$packageCount = (Get-Content requirements.txt | Where-Object { $_ -match '^[a-z]' }).Count

Write-Host "✅ requirements.txt has been updated successfully!" -ForegroundColor Green
Write-Host "📋 Total packages: $packageCount" -ForegroundColor Yellow

# Test simple du système adaptatif

Write-Host "Test de détection Windows..." -ForegroundColor Cyan

# Détecter la version
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
$editionID = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "EditionID" -ErrorAction SilentlyContinue).EditionID

Write-Host "Version: $($osInfo.Version)"
Write-Host "Build: $($osInfo.BuildNumber)"
Write-Host "Edition: $editionID"

# Déterminer le type
$isHome = $editionID -like "*Home*" -or $editionID -eq "Core"
$isPro = $editionID -like "*Pro*"
$isEnterprise = $editionID -like "*Enterprise*"

if ($isHome) { Write-Host "Type: Home" -ForegroundColor Yellow }
elseif ($isPro) { Write-Host "Type: Pro" -ForegroundColor Blue }
elseif ($isEnterprise) { Write-Host "Type: Enterprise" -ForegroundColor Green }
else { Write-Host "Type: Inconnu" -ForegroundColor Red }

# Charger le baseline
$baselinePath = ".\data\baselines\windows\msft_windows_11_24h2_machine.json"
$jsonContent = Get-Content -Path $baselinePath -Raw
$baselineData = ConvertFrom-Json -InputObject $jsonContent

# Déterminer les exclusions
$exclusions = @()
if ($isHome) {
    $exclusions = $baselineData.variants.Home.excludeFindings
    Write-Host "Exclusions Home: $($exclusions.Count) findings"
}

# Filtrer
$compatibleFindings = $baselineData.findings | Where-Object { $_.id -notin $exclusions }
Write-Host "Findings compatibles: $($compatibleFindings.Count) / $($baselineData.findings.Count)"

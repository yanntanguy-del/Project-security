# Système adaptatif de détection Windows et configuration HardeningKitty

function Get-WindowsVersionInfo {
    param()
    
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $productType = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "EditionID" -ErrorAction SilentlyContinue).EditionID
    
    $version = @{
        Version = $osInfo.Version
        Build = $osInfo.BuildNumber
        Architecture = $osInfo.OSArchitecture
        ProductType = $productType
        IsHome = $productType -like "*Home*" -or $productType -eq "Core"
        IsPro = $productType -like "*Pro*"
        IsEnterprise = $productType -like "*Enterprise*"
    }
    
    return $version
}

function Get-CompatibleFindings {
    param(
        [string]$BaselinePath,
        [hashtable]$VersionInfo
    )
    
    # Charger le fichier baseline
    $jsonContent = Get-Content -Path $BaselinePath -Raw
    $baselineData = ConvertFrom-Json -InputObject $jsonContent
    
    # Déterminer les exclusions selon la version
    $exclusions = @()
    
    if ($VersionInfo.IsHome) {
        Write-Host " Windows Home détecté - Exclusion des features non disponibles"
        $exclusions = $baselineData.variants.Home.excludeFindings
    }
    elseif ($VersionInfo.IsPro) {
        Write-Host " Windows Pro détecté - Exclusion partielle"
        $exclusions = $baselineData.variants.Pro.excludeFindings
    }
    elseif ($VersionInfo.IsEnterprise) {
        Write-Host " Windows Enterprise détecté - Toutes les features disponibles"
        $exclusions = @()
    }
    
    # Filtrer les findings
    $allFindings = $baselineData.findings
    $compatibleFindings = $allFindings | Where-Object { $_.id -notin $exclusions }
    
    # Créer un fichier temporaire avec les findings compatibles
    $tempBaseline = $baselineData.Clone()
    $tempBaseline.findings = $compatibleFindings
    
    $tempPath = "$env:TEMP\adaptive_baseline_$($VersionInfo.ProductType).json"
    $tempBaseline | ConvertTo-Json -Depth 10 | Set-Content -Path $tempPath
    
    # Retourner les informations pour affichage
    return @{
        TempPath = $tempPath
        TotalFindings = $allFindings.Count
        CompatibleFindings = $compatibleFindings.Count
    }
}

function Invoke-AdaptiveHardeningKitty {
    param(
        [string]$BaselinePath = ".\data\baselines\windows\msft_windows_11_24h2_machine.json"
    )
    
    Write-Host "🔍 Détection de l'environnement Windows..." -ForegroundColor Cyan
    
    # Détecter la version
    $versionInfo = Get-WindowsVersionInfo
    
    Write-Host "📊 Version détectée :"
    Write-Host "   - Version : $($versionInfo.Version)" -ForegroundColor Gray
    Write-Host "   - Build : $($versionInfo.Build)" -ForegroundColor Gray  
    Write-Host "   - Architecture : $($versionInfo.Architecture)" -ForegroundColor Gray
    Write-Host "   - Édition : $($versionInfo.ProductType)" -ForegroundColor Gray
    
    if ($versionInfo.IsHome) { Write-Host "   - Type : Home" -ForegroundColor Yellow }
    elseif ($versionInfo.IsPro) { Write-Host "   - Type : Pro" -ForegroundColor Blue }
    elseif ($versionInfo.IsEnterprise) { Write-Host "   - Type : Enterprise" -ForegroundColor Green }
    
    # Générer le baseline adaptatif
    Write-Host "`n⚙️  Génération du baseline adaptatif..." -ForegroundColor Cyan
    $adaptiveBaseline = Get-CompatibleFindings -BaselinePath $BaselinePath -VersionInfo $versionInfo
    
    Write-Host "✅ Baseline adaptatif créé : $($result.TempPath)" -ForegroundColor Green
    Write-Host "📈 Findings inclus : $($result.TotalFindings) → $($result.CompatibleFindings)" -ForegroundColor Cyan
    
    # Lancer HardeningKitty avec le baseline adaptatif
    Write-Host "`n🚀 Lancement de HardeningKitty avec configuration adaptative..." -ForegroundColor Green
    
    Import-Module ".\HardeningKitty\HardeningKitty.psm1" -Force
    
    $reportPath = ".\reports\adaptive_scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    Invoke-HardeningKitty -File $result.TempPath -Mode Audit -Report $reportPath -Verbose
    
    Write-Host "`n📋 Rapport généré : $reportPath" -ForegroundColor Green
    
    # Nettoyer seulement si le fichier existe
    if ($result.TempPath -and (Test-Path $result.TempPath)) {
        Remove-Item $result.TempPath -Force -ErrorAction SilentlyContinue
        Write-Host "🧹 Fichier temporaire nettoyé" -ForegroundColor Gray
    }
}

# Point d'entrée principal
if ($MyInvocation.InvocationName -eq $MyInvocation.MyCommand.Name) {
    Invoke-AdaptiveHardeningKitty
} elseif (-not $MyInvocation.InvocationName) {
    # Exécuté directement depuis PowerShell
    Invoke-AdaptiveHardeningKitty
}

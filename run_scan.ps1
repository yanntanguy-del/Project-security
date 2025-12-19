# Application de Sécurité Multi-OS Adaptative

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Variables globales
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

# Fonctions de détection multi-OS
function Get-SystemInfo {
    param()
    
    $osInfo = @{}
    
    if ($IsWindows) {
        # Windows
        $osInfo.Type = "Windows"
        $osInfo.Version = (Get-CimInstance -ClassName Win32_OperatingSystem).Version
        $osInfo.Build = (Get-CimInstance -ClassName Win32_OperatingSystem).BuildNumber
        $osInfo.Architecture = (Get-CimInstance -ClassName Win32_OperatingSystem).OSArchitecture
        $osInfo.Edition = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "EditionID" -ErrorAction SilentlyContinue).EditionID
        
        # Déterminer la variante Windows
        if ($osInfo.Edition -like "*Home*" -or $osInfo.Edition -eq "Core") {
            $osInfo.Variant = "Home"
        } elseif ($osInfo.Edition -like "*Pro*") {
            $osInfo.Variant = "Pro"
        } elseif ($osInfo.Edition -like "*Enterprise*") {
            $osInfo.Variant = "Enterprise"
        } else {
            $osInfo.Variant = "Unknown"
        }
        
        # Détecter le fabricant OEM
        $osInfo.OEM = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer
        $osInfo.Model = (Get-CimInstance -ClassName Win32_ComputerSystem).Model
        
        $osInfo.BaselinePath = ".\data\baselines\windows\msft_windows_11_24h2_machine.json"
        $osInfo.Color = "Blue"
        
    } elseif ($IsLinux) {
        # Linux
        $osInfo.Type = "Linux"
        $osInfo.Distribution = (Get-Content /etc/os-release | Where-Object { $_ -match "^ID=" } | ForEach-Object { $_ -replace 'ID=', '' -replace '"' } | Select-Object -First 1)
        $osInfo.Version = (Get-Content /etc/os-release | Where-Object { $_ -match "^VERSION_ID=" } | ForEach-Object { $_ -replace 'VERSION_ID=', '' -replace '"' } | Select-Object -First 1)
        $osInfo.Architecture = uname -m
        $osInfo.Variant = $osInfo.Distribution
        
        # Détecter le fabricant
        if (Test-Path /sys/class/dmi/id/sys_vendor) {
            $osInfo.OEM = Get-Content /sys/class/dmi/id/sys_vendor
        } else {
            $osInfo.OEM = "Unknown"
        }
        if (Test-Path /sys/class/dmi/id/product_name) {
            $osInfo.Model = Get-Content /sys/class/dmi/id/product_name
        } else {
            $osInfo.Model = "Unknown"
        }
        
        # Déterminer le baseline selon la distribution
        switch ($osInfo.Distribution) {
            "ubuntu" { 
                $osInfo.BaselinePath = ".\data\baselines\linux\cis_ubuntu_2404_machine.json"
                $osInfo.Color = "Orange"
            }
            "debian" { 
                $osInfo.BaselinePath = ".\data\baselines\linux\cis_debian_12_machine.json"
                $osInfo.Color = "Red"
            }
            "fedora" { 
                $osInfo.BaselinePath = ".\data\baselines\linux\cis_fedora_40_machine.json"
                $osInfo.Color = "Blue"
            }
            "arch" { 
                $osInfo.BaselinePath = ".\data\baselines\linux\cis_arch_machine.json"
                $osInfo.Color = "Purple"
            }
            default { 
                $osInfo.BaselinePath = ".\data\baselines\linux\cis_ubuntu_2404_machine.json"
                $osInfo.Color = "Gray"
            }
        }
        
    } elseif ($IsMacOS) {
        # macOS
        $osInfo.Type = "macOS"
        $osInfo.Version = sw_vers -productVersion
        $osInfo.Build = sw_vers -buildVersion
        $osInfo.Architecture = uname -m
        $osInfo.Variant = "macOS"
        
        # Détecter le modèle Mac
        $osInfo.OEM = "Apple"
        $osInfo.Model = system_profiler SPHardwareDataType | grep "Model Name" | awk -F': ' '{print $2}'
        
        # Déterminer le baseline selon la version
        if ($osInfo.Version -like "14*") {
            $osInfo.BaselinePath = ".\data\baselines\macos\cis_macos_sonoma_machine.json"
            $osInfo.Color = "Green"
        } elseif ($osInfo.Version -like "15*") {
            $osInfo.BaselinePath = ".\data\baselines\macos\cis_macos_sequoia_machine.json"
            $osInfo.Color = "Green"
        } else {
            $osInfo.BaselinePath = ".\data\baselines\macos\cis_macos_sonoma_machine.json"
            $osInfo.Color = "LightGreen"
        }
    } else {
        # Inconnu
        $osInfo.Type = "Unknown"
        $osInfo.BaselinePath = $null
        $osInfo.Color = "Gray"
    }
    
    return $osInfo
}

function Get-CompatibleFindings {
    param(
        [hashtable]$SystemInfo
    )
    
    if (-not $SystemInfo.BaselinePath -or -not (Test-Path $SystemInfo.BaselinePath)) {
        Write-Host "Baseline non trouve pour $($SystemInfo.Type)" -ForegroundColor Red
        return @{
            TotalFindings = 0
            CompatibleFindings = 0
            Exclusions = 0
            Findings = @()
        }
    }
    
    # Charger le baseline
    $jsonContent = Get-Content -Path $SystemInfo.BaselinePath -Raw
    $baselineData = ConvertFrom-Json -InputObject $jsonContent
    
    # Pour Windows, appliquer les exclusions de variante et OEM
    if ($SystemInfo.Type -eq "Windows" -and $baselineData.variants) {
        $exclusions = @()
        
        # Exclusions de variante
        if ($SystemInfo.Variant -eq "Home") {
            $exclusions += $baselineData.variants.Home.excludeFindings
        } elseif ($SystemInfo.Variant -eq "Pro") {
            $exclusions += $baselineData.variants.Pro.excludeFindings
        }
        
        # Exclusions OEM
        if ($baselineData.variants -and $baselineData.variants.$($SystemInfo.OEM)) {
            $exclusions += $baselineData.variants.$($SystemInfo.OEM).excludeFindings
        }
        
        $allFindings = $baselineData.findings
        $compatibleFindings = $allFindings | Where-Object { $_.id -notin $exclusions }
        
        return @{
            TotalFindings = $allFindings.Count
            CompatibleFindings = $compatibleFindings.Count
            Exclusions = $exclusions.Count
            Findings = $compatibleFindings
        }
    } else {
        # Pour Linux/macOS, utiliser tous les findings
        $allFindings = $baselineData.findings
        
        return @{
            TotalFindings = $allFindings.Count
            CompatibleFindings = $allFindings.Count
            Exclusions = 0
            Findings = $allFindings
        }
    }
}

function Start-PreliminaryScan {
    Write-Host "Lancement du scan préliminaire..." -ForegroundColor Cyan
    
    # Détecter le système
    $systemInfo = Get-SystemInfo
    
    # Afficher les informations système
    Write-Host "`nSYSTEME DÉTECTÉ : $($systemInfo.Type.ToUpper())" -ForegroundColor $systemInfo.Color
    
    if ($systemInfo.Type -eq "Windows") {
        Write-Host "Version : $($systemInfo.Version)" -ForegroundColor White
        Write-Host "Build : $($systemInfo.Build)" -ForegroundColor White
        Write-Host "Architecture : $($systemInfo.Architecture)" -ForegroundColor White
        Write-Host "Edition : $($systemInfo.Edition)" -ForegroundColor White
        Write-Host "Variante : $($systemInfo.Variant)" -ForegroundColor $systemInfo.Color
        Write-Host "Fabricant : $($systemInfo.OEM)" -ForegroundColor White
        Write-Host "Modèle : $($systemInfo.Model)" -ForegroundColor White
    } elseif ($systemInfo.Type -eq "Linux") {
        Write-Host "Distribution : $($systemInfo.Distribution)" -ForegroundColor White
        Write-Host "Version : $($systemInfo.Version)" -ForegroundColor White
        Write-Host "Architecture : $($systemInfo.Architecture)" -ForegroundColor White
        Write-Host "Fabricant : $($systemInfo.OEM)" -ForegroundColor White
        Write-Host "Modèle : $($systemInfo.Model)" -ForegroundColor White
    } elseif ($systemInfo.Type -eq "macOS") {
        Write-Host "Version : $($systemInfo.Version)" -ForegroundColor White
        Write-Host "Build : $($systemInfo.Build)" -ForegroundColor White
        Write-Host "Architecture : $($systemInfo.Architecture)" -ForegroundColor White
        Write-Host "Modèle : $($systemInfo.Model)" -ForegroundColor White
    }
    
    # Analyser les findings
    $findingsInfo = Get-CompatibleFindings -SystemInfo $systemInfo
    
    Write-Host "`nANALYSE DES FINDINGS" -ForegroundColor Cyan
    Write-Host "Baseline : $($systemInfo.BaselinePath)" -ForegroundColor Gray
    Write-Host "Total findings : $($findingsInfo.TotalFindings)" -ForegroundColor White
    if ($findingsInfo.Exclusions -gt 0) {
        Write-Host "Findings exclus : $($findingsInfo.Exclusions)" -ForegroundColor Red
        Write-Host "Findings pertinents : $($findingsInfo.CompatibleFindings)" -ForegroundColor Green
        $optimization = [math]::Round((($findingsInfo.Exclusions / $findingsInfo.TotalFindings) * 100), 2)
        Write-Host "Optimisation : $optimization% de réduction" -ForegroundColor Yellow
    } else {
        Write-Host "Findings scannés : $($findingsInfo.CompatibleFindings)" -ForegroundColor Green
    }
    
    return @{
        SystemInfo = $systemInfo
        FindingsInfo = $findingsInfo
    }
}

function Start-SystemScan {
    param([hashtable]$PreliminaryResults)
    
    Write-Host "`nLancement du scan système adaptatif..." -ForegroundColor Green
    
    try {
        # Importer HardeningKitty
        Import-Module ".\HardeningKitty\HardeningKitty.psm1" -Force
        
        # Créer un baseline adaptatif temporaire
        $adaptiveBaseline = @{
            metadata = @{
                name = "Adaptive Security Baseline"
                version = "1.0"
                osType = $PreliminaryResults.SystemInfo.Type
                osVariant = $PreliminaryResults.SystemInfo.Variant
                oem = $PreliminaryResults.SystemInfo.OEM
                model = $PreliminaryResults.SystemInfo.Model
                generated = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            }
            findings = $PreliminaryResults.FindingsInfo.Findings
        }
        
        $tempPath = "$env:TEMP\adaptive_baseline_$($PreliminaryResults.SystemInfo.Type)_$($PreliminaryResults.SystemInfo.Variant).json"
        $adaptiveBaseline | ConvertTo-Json -Depth 10 | Set-Content -Path $tempPath
        
        # Créer le rapport
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $reportPath = ".\reports\hardeningkitty_report_$timestamp.csv"
        
        # Lancer le scan
        Invoke-HardeningKitty -File $tempPath -Mode Audit -Report $reportPath -Verbose
        
        # Afficher le résumé final
        $systemInfo = $PreliminaryResults.SystemInfo
        $findingsInfo = $PreliminaryResults.FindingsInfo
        
        $summaryText = "Scan système terminé avec succès !`n`nRésumé :`n• Système : $($systemInfo.Type) $($systemInfo.Variant)`n• Fabricant : $($systemInfo.OEM)`n• Modèle : $($systemInfo.Model)`n• Findings scannés : $($findingsInfo.CompatibleFindings)"
        
        if ($findingsInfo.Exclusions -gt 0) {
            $optimization = [math]::Round((($findingsInfo.Exclusions / $findingsInfo.TotalFindings) * 100), 2)
            $summaryText += "`n• Optimisation : $optimization% de réduction"
        }
        
        $summaryText += "`n• Rapport : $reportPath`n`nVoir la console pour les détails complets."
        
        [System.Windows.Forms.MessageBox]::Show($summaryText, "Scan Terminé", "OK", "Information")
        
        # Nettoyer le fichier temporaire
        Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Erreur lors du scan : $($_.Exception.Message)", "Erreur", "OK", "Error")
    }
}

# Création de l'interface graphique
$form = New-Object System.Windows.Forms.Form
$form.Text = "Security Scanner Multi-OS Adaptatif"
$form.Size = New-Object System.Drawing.Size(650, 500)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false

# Titre
$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text = "Security Scanner Multi-OS"
$titleLabel.Font = New-Object System.Drawing.Font("Arial", 18, [System.Drawing.FontStyle]::Bold)
$titleLabel.ForeColor = [System.Drawing.Color]::DarkBlue
$titleLabel.Location = New-Object System.Drawing.Point(50, 20)
$titleLabel.Size = New-Object System.Drawing.Size(550, 35)
$form.Controls.Add($titleLabel)

# Description
$descLabel = New-Object System.Windows.Forms.Label
$descLabel.Text = "Application de sécurité multi-plateforme qui adapte automatiquement les scans selon votre système d'exploitation, version et modèle.`nSupporte Windows, Linux et macOS avec optimisation automatique des findings."
$descLabel.Location = New-Object System.Drawing.Point(50, 70)
$descLabel.Size = New-Object System.Drawing.Size(550, 60)
$descLabel.ForeColor = [System.Drawing.Color]::DarkGray
$form.Controls.Add($descLabel)

# Bouton Scan Préliminaire
$btnPreliminary = New-Object System.Windows.Forms.Button
$btnPreliminary.Text = "Scan Préliminaire"
$btnPreliminary.Size = New-Object System.Drawing.Size(200, 45)
$btnPreliminary.Location = New-Object System.Drawing.Point(60, 150)
$btnPreliminary.BackColor = [System.Drawing.Color]::LightBlue
$btnPreliminary.ForeColor = [System.Drawing.Color]::White
$btnPreliminary.Font = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Bold)
$btnPreliminary.Add_Click({
    $this.Enabled = $false
    $this.Text = "Analyse en cours..."
    $form.Refresh()
    
    $script:preliminaryResults = Start-PreliminaryScan
    
    $this.Enabled = $true
    $this.Text = "Scan Préliminaire"
    
    if ($preliminaryResults) {
        $systemInfo = $preliminaryResults.SystemInfo
        $findingsInfo = $preliminaryResults.FindingsInfo
        
        $resultText = "Analyse préliminaire terminée !`n`nSystème : $($systemInfo.Type) $($systemInfo.Variant)`nFabricant : $($systemInfo.OEM)`nModèle : $($systemInfo.Model)`nBaseline : $($systemInfo.BaselinePath)`n`nFindings :`n• Total : $($findingsInfo.TotalFindings)"
        
        if ($findingsInfo.Exclusions -gt 0) {
            $resultText += "`n• Exclus : $($findingsInfo.Exclusions)`n• Pertinents : $($findingsInfo.CompatibleFindings)"
            $optimization = [math]::Round((($findingsInfo.Exclusions / $findingsInfo.TotalFindings) * 100), 2)
            $resultText += "`n• Optimisation : $optimization%"
        } else {
            $resultText += "`n• Scannés : $($findingsInfo.CompatibleFindings)"
        }
        
        [System.Windows.Forms.MessageBox]::Show($resultText, "Analyse Terminée", "OK", "Information")
    }
})
$form.Controls.Add($btnPreliminary)

# Bouton Scan Système
$btnSystem = New-Object System.Windows.Forms.Button
$btnSystem.Text = "Scan Système"
$btnSystem.Size = New-Object System.Drawing.Size(200, 45)
$btnSystem.Location = New-Object System.Drawing.Point(390, 150)
$btnSystem.BackColor = [System.Drawing.Color]::LightGreen
$btnSystem.ForeColor = [System.Drawing.Color]::White
$btnSystem.Font = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Bold)
$btnSystem.Add_Click({
    $this.Enabled = $false
    $this.Text = "Scan en cours..."
    $form.Refresh()
    
    if (-not $script:preliminaryResults) {
        # Si pas de scan préliminaire, en faire un automatiquement
        $script:preliminaryResults = Start-PreliminaryScan
    }
    
    Start-SystemScan -PreliminaryResults $script:preliminaryResults
    
    $this.Enabled = $true
    $this.Text = "Scan Système"
})
$form.Controls.Add($btnSystem)

# Bouton Quitter
$btnExit = New-Object System.Windows.Forms.Button
$btnExit.Text = "Quitter"
$btnExit.Size = New-Object System.Drawing.Size(100, 35)
$btnExit.Location = New-Object System.Drawing.Point(275, 250)
$btnExit.Add_Click({ $form.Close() })
$form.Controls.Add($btnExit)

# Status
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = "Prêt à analyser votre système multi-OS"
$statusLabel.Location = New-Object System.Drawing.Point(50, 350)
$statusLabel.Size = New-Object System.Drawing.Size(550, 30)
$statusLabel.ForeColor = [System.Drawing.Color]::Green
$statusLabel.Font = New-Object System.Drawing.Font("Arial", 10)
$form.Controls.Add($statusLabel)

# Info supplémentaire
$infoLabel = New-Object System.Windows.Forms.Label
$infoLabel.Text = "Supporte : Windows (Home/Pro/Enterprise) • Linux (Ubuntu/Debian/Fedora/Arch) • macOS (Sonoma/Sequoia)`nOptimisation automatique selon fabricant et modèle (Dell, HP, Lenovo, ASUS, Acer, Apple)"
$infoLabel.Location = New-Object System.Drawing.Point(50, 400)
$infoLabel.Size = New-Object System.Drawing.Size(550, 50)
$infoLabel.ForeColor = [System.Drawing.Color]::Gray
$infoLabel.Font = New-Object System.Drawing.Font("Arial", 9)
$form.Controls.Add($infoLabel)

# Variable pour stocker les résultats du scan préliminaire
$script:preliminaryResults = $null

# Afficher la fenêtre
[void]$form.ShowDialog()

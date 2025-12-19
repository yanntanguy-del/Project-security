# Application de Sécurité avec Scan Préliminaire et Système Adaptatif

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Variables globales
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$adaptiveScript = Join-Path $scriptPath "adaptive_scan.ps1"

# Fonctions de scan
function Start-PreliminaryScan {
    Write-Host "🔍 Lancement du scan préliminaire..." -ForegroundColor Cyan
    
    # Détecter l'environnement
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $editionID = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "EditionID" -ErrorAction SilentlyContinue).EditionID
    
    $isHome = $editionID -like "*Home*" -or $editionID -eq "Core"
    $isPro = $editionID -like "*Pro*"
    $isEnterprise = $editionID -like "*Enterprise*"
    
    # Afficher les informations système
    Write-Host "`n📊 INFORMATIONS SYSTÈME" -ForegroundColor Yellow
    Write-Host "Version Windows : $($osInfo.Version)" -ForegroundColor White
    Write-Host "Build : $($osInfo.BuildNumber)" -ForegroundColor White
    Write-Host "Architecture : $($osInfo.OSArchitecture)" -ForegroundColor White
    Write-Host "Édition : $editionID" -ForegroundColor White
    
    if ($isHome) { Write-Host "Type : HOME" -ForegroundColor Yellow }
    elseif ($isPro) { Write-Host "Type : PRO" -ForegroundColor Blue }
    elseif ($isEnterprise) { Write-Host "Type : ENTERPRISE" -ForegroundColor Green }
    else { Write-Host "Type : INCONNU" -ForegroundColor Red }
    
    # Charger le baseline
    $baselinePath = ".\data\baselines\windows\msft_windows_11_24h2_machine.json"
    $jsonContent = Get-Content -Path $baselinePath -Raw
    $baselineData = ConvertFrom-Json -InputObject $jsonContent
    
    # Analyser les findings
    $totalFindings = $baselineData.findings.Count
    $exclusions = @()
    
    if ($isHome) {
        $exclusions = $baselineData.variants.Home.excludeFindings
        Write-Host "`n🏠 WINDOWS HOME DÉTECTÉ" -ForegroundColor Yellow
    }
    elseif ($isPro) {
        $exclusions = $baselineData.variants.Pro.excludeFindings
        Write-Host "`n💼 WINDOWS PRO DÉTECTÉ" -ForegroundColor Blue
    }
    elseif ($isEnterprise) {
        Write-Host "`n🏢 WINDOWS ENTERPRISE DÉTECTÉ" -ForegroundColor Green
    }
    
    $compatibleFindings = $baselineData.findings | Where-Object { $_.id -notin $exclusions }
    
    Write-Host "`n📈 ANALYSE DES FINDINGS" -ForegroundColor Cyan
    Write-Host "Total findings dans la base : $totalFindings" -ForegroundColor White
    Write-Host "Findings exclus : $($exclusions.Count)" -ForegroundColor Red
    Write-Host "Findings qui seront scannés : $($compatibleFindings.Count)" -ForegroundColor Green
    Write-Host "Optimisation : $([math]::Round((($exclusions.Count / $totalFindings) * 100), 2))% de réduction" -ForegroundColor Yellow
    
    return @{
        TotalFindings = $totalFindings
        ExcludedFindings = $exclusions.Count
        CompatibleFindings = $compatibleFindings.Count
        SystemType = if ($isHome) { "Home" } elseif ($isPro) { "Pro" } else { "Enterprise" }
        VersionInfo = $osInfo
        EditionID = $editionID
    }
}

function Start-SystemScan {
    param([hashtable]$PreliminaryResults)
    
    Write-Host "`n🚀 Lancement du scan système adaptatif..." -ForegroundColor Green
    
    if (-not (Test-Path $adaptiveScript)) {
        [System.Windows.Forms.MessageBox]::Show("Le script adaptatif n'a pas été trouvé", "Erreur", "OK", "Error")
        return
    }
    
    try {
        # Exécuter le scan adaptatif
        $result = & $adaptiveScript
        
        # Afficher le résumé final
        [System.Windows.Forms.MessageBox]::Show(
            "Scan système terminé avec succès !`n`nRésumé :`n• Système : $($PreliminaryResults.SystemType)`n• Findings scannés : $($PreliminaryResults.CompatibleFindings)`n• Optimisation : $([math]::Round((($PreliminaryResults.ExcludedFindings / $PreliminaryResults.TotalFindings) * 100), 2))%`n`nVoir la console pour les détails complets.", 
            "Scan Terminé", 
            "OK", 
            "Information"
        )
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Erreur lors du scan : $($_.Exception.Message)", "Erreur", "OK", "Error")
    }
}

# Création de l'interface graphique
$form = New-Object System.Windows.Forms.Form
$form.Text = "Security Scanner - Analyse Adaptative"
$form.Size = New-Object System.Drawing.Size(600, 450)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false

# Titre
$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text = "Security Scanner - Analyse Adaptative"
$titleLabel.Font = New-Object System.Drawing.Font("Arial", 18, [System.Drawing.FontStyle]::Bold)
$titleLabel.ForeColor = [System.Drawing.Color]::DarkBlue
$titleLabel.Location = New-Object System.Drawing.Point(50, 20)
$titleLabel.Size = New-Object System.Drawing.Size(500, 35)
$form.Controls.Add($titleLabel)

# Description
$descLabel = New-Object System.Windows.Forms.Label
$descLabel.Text = "Application de sécurité qui adapte automatiquement les scans selon votre version Windows.`nLe scan préliminaire analyse votre système et optimise les findings pertinents."
$descLabel.Location = New-Object System.Drawing.Point(50, 70)
$descLabel.Size = New-Object System.Drawing.Size(500, 50)
$descLabel.ForeColor = [System.Drawing.Color]::DarkGray
$form.Controls.Add($descLabel)

# Bouton Scan Préliminaire
$btnPreliminary = New-Object System.Windows.Forms.Button
$btnPreliminary.Text = "Scan Préliminaire"
$btnPreliminary.Size = New-Object System.Drawing.Size(180, 45)
$btnPreliminary.Location = New-Object System.Drawing.Point(80, 150)
$btnPreliminary.BackColor = [System.Drawing.Color]::LightBlue
$btnPreliminary.ForeColor = [System.Drawing.Color]::White
$btnPreliminary.Font = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Bold)
$btnPreliminary.Add_Click({
    $this.Enabled = $false
    $this.Text = "Analyse en cours..."
    $form.Refresh()
    
    $results = Start-PreliminaryScan
    
    $this.Enabled = $true
    $this.Text = "Scan Préliminaire"
    
    [System.Windows.Forms.MessageBox]::Show(
        "Analyse préliminaire terminée !`n`nRésultats :`n• Version : $($results.VersionInfo.Version)`n• Type : $($results.SystemType)`n• Findings totaux : $($results.TotalFindings)`n• Findings exclus : $($results.ExcludedFindings)`n• Findings pertinents : $($results.CompatibleFindings)`n`nCliquez sur 'Scan Système' pour lancer l'analyse complète.", 
        "Analyse Terminée", 
        "OK", 
        "Information"
    )
})
$form.Controls.Add($btnPreliminary)

# Bouton Scan Système
$btnSystem = New-Object System.Windows.Forms.Button
$btnSystem.Text = "Scan Système"
$btnSystem.Size = New-Object System.Drawing.Size(180, 45)
$btnSystem.Location = New-Object System.Drawing.Point(340, 150)
$btnSystem.BackColor = [System.Drawing.Color]::LightGreen
$btnSystem.ForeColor = [System.Drawing.Color]::White
$btnSystem.Font = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Bold)
$btnSystem.Add_Click({
    $this.Enabled = $false
    $this.Text = "Scan en cours..."
    $form.Refresh()
    
    $preliminaryResults = Start-PreliminaryScan
    Start-SystemScan -PreliminaryResults $preliminaryResults
    
    $this.Enabled = $true
    $this.Text = "Scan Système"
})
$form.Controls.Add($btnSystem)

# Bouton Quitter
$btnExit = New-Object System.Windows.Forms.Button
$btnExit.Text = "Quitter"
$btnExit.Size = New-Object System.Drawing.Size(100, 35)
$btnExit.Location = New-Object System.Drawing.Point(250, 250)
$btnExit.Add_Click({ $form.Close() })
$form.Controls.Add($btnExit)

# Status
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = "Prêt à analyser votre système"
$statusLabel.Location = New-Object System.Drawing.Point(50, 320)
$statusLabel.Size = New-Object System.Drawing.Size(500, 30)
$statusLabel.ForeColor = [System.Drawing.Color]::Green
$statusLabel.Font = New-Object System.Drawing.Font("Arial", 10)
$form.Controls.Add($statusLabel)

# Afficher la fenêtre
[void]$form.ShowDialog()

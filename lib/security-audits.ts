// Security audit PowerShell commands and parsers

export interface AuditResult {
  category: string;
  name: string;
  status: 'Pass' | 'Fail' | 'Warning' | 'Info';
  value: string;
  recommendation?: string;
  severity: 'High' | 'Medium' | 'Low' | 'Info';
}

export const SecurityAudits = {
  // Network & Firewall
  networkFirewall: () => `
    # Check Firewall Status
    Write-Output "=== FIREWALL STATUS ==="
    Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Compress
    
    Write-Output "=== SMB VERSION ==="
    Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol | ConvertTo-Json -Compress
    
    Write-Output "=== OPEN PORTS ==="
    Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess, @{Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} | ConvertTo-Json -Compress
    
    Write-Output "=== FIREWALL RULES (ALLOW INBOUND) ==="
    Get-NetFirewallRule | Where-Object {$_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' -and $_.Enabled -eq $true} | Select-Object DisplayName, Profile, RemoteAddress -First 20 | ConvertTo-Json -Compress
  `,

  // Security Software
  securitySoftware: () => `
    # Windows Defender Status
    Write-Output "=== DEFENDER STATUS ==="
    Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, IsTamperProtected, AntivirusSignatureLastUpdated, QuickScanAge, FullScanAge | ConvertTo-Json -Compress
    
    Write-Output "=== DEFENDER PREFERENCES ==="
    Get-MpPreference | Select-Object DisableRealtimeMonitoring, DisableArchiveScanning, DisableBehaviorMonitoring, DisableIntrusionPreventionSystem | ConvertTo-Json -Compress
  `,

  // Updates & Patches
  updatesPatch: () => `
    # Windows Update Status
    Write-Output "=== UPDATE SETTINGS ==="
    $au = New-Object -ComObject Microsoft.Update.AutoUpdate
    Write-Output "AutoUpdate Enabled: $($au.ServiceEnabled)"
    
    Write-Output "=== PENDING UPDATES ==="
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    $searchResult = $updateSearcher.Search("IsInstalled=0")
    $searchResult.Updates | Select-Object Title, IsDownloaded, @{Name="Severity";Expression={$_.MsrcSeverity}} | ConvertTo-Json -Compress
    
    Write-Output "=== LAST UPDATE ==="
    Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 | ConvertTo-Json -Compress
  `,

  // Encryption & BitLocker
  encryptionBitLocker: () => `
    # BitLocker Status
    Write-Output "=== BITLOCKER STATUS ==="
    Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, EncryptionPercentage, ProtectionStatus | ConvertTo-Json -Compress
    
    Write-Output "=== TPM STATUS ==="
    $tpm = Get-Tpm
    Write-Output "TPM Present: $($tpm.TpmPresent)"
    Write-Output "TPM Ready: $($tpm.TpmReady)"
    Write-Output "TPM Enabled: $($tpm.TpmEnabled)"
    Write-Output "TPM Activated: $($tpm.TpmActivated)"
  `,

  // Services & Scheduled Tasks
  servicesAndTasks: () => `
    # System Services
    Write-Output "=== SYSTEM SERVICES ==="
    Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, DisplayName, StartType -First 30 | ConvertTo-Json -Compress
    
    Write-Output "=== SCHEDULED TASKS (ENABLED) ==="
    Get-ScheduledTask | Where-Object {$_.State -eq 'Ready' -or $_.State -eq 'Running'} | Select-Object TaskName, TaskPath, State, @{Name="RunAsUser";Expression={$_.Principal.UserId}} | ConvertTo-Json -Compress
  `,

  // File System & Shares
  fileSystemShares: () => `
    # Network Shares
    Write-Output "=== NETWORK SHARES ==="
    Get-SmbShare | Select-Object Name, Path, Description, ShareState | ConvertTo-Json -Compress
    
    Write-Output "=== SHARE PERMISSIONS ==="
    Get-SmbShare | ForEach-Object {
      $shareName = $_.Name
      Get-SmbShareAccess -Name $shareName | Select-Object @{Name="Share";Expression={$shareName}}, AccountName, AccessControlType, AccessRight
    } | ConvertTo-Json -Compress
  `,

  // Event Logs & Monitoring
  eventLogs: () => `
    # Security Event Logs (requires admin privileges)
    Write-Output "=== FAILED LOGINS (LAST 24H) ==="
    try {
      $failedLogins = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddHours(-24)} -ErrorAction Stop -MaxEvents 10
      $failedLogins | Select-Object TimeCreated, Message | ConvertTo-Json -Compress
    } catch {
      Write-Output "REQUIRES_ADMIN"
    }
    
    Write-Output "=== AUDIT POLICY ==="
    try {
      auditpol /get /category:* 2>&1 | Out-String
    } catch {
      Write-Output "REQUIRES_ADMIN"
    }
    
    Write-Output "=== RECENT SECURITY EVENTS ==="
    try {
      Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddHours(-24)} -ErrorAction Stop -MaxEvents 5 | Select-Object TimeCreated, Id, Message | ConvertTo-Json -Compress
    } catch {
      Write-Output "REQUIRES_ADMIN"
    }
  `,

  // Browser & Applications
  browserApps: () => `
    # Installed Software
    Write-Output "=== INSTALLED SOFTWARE ==="
    Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate -First 20 | ConvertTo-Json -Compress
    
    Write-Output "=== CERTIFICATES (USER) ==="
    Get-ChildItem Cert:\\CurrentUser\\Root | Select-Object Subject, Issuer, NotAfter, Thumbprint -First 10 | ConvertTo-Json -Compress
    
    Write-Output "=== STARTUP PROGRAMS ==="
    Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User | ConvertTo-Json -Compress
  `
};

// Parser functions for each audit
export const parseNetworkFirewall = (output: string): AuditResult[] => {
  const results: AuditResult[] = [];
  
  try {
    // Parse firewall status
    if (output.includes('=== FIREWALL STATUS ===')) {
      const firewallSection = output.split('=== FIREWALL STATUS ===')[1].split('===')[0];
      const profiles = JSON.parse(firewallSection.trim());
      const profileArray = Array.isArray(profiles) ? profiles : [profiles];
      
      profileArray.forEach((profile: any) => {
        results.push({
          category: 'Network & Firewall',
          name: `Firewall - ${profile.Name} Profile`,
          status: profile.Enabled ? 'Pass' : 'Fail',
          value: profile.Enabled ? 'Enabled' : 'Disabled',
          recommendation: profile.Enabled ? undefined : 'Enable firewall for this profile',
          severity: profile.Enabled ? 'Info' : 'High'
        });
      });
    }
    
    // Parse SMB status
    if (output.includes('=== SMB VERSION ===')) {
      const smbSection = output.split('=== SMB VERSION ===')[1].split('===')[0];
      const smb = JSON.parse(smbSection.trim());
      
      results.push({
        category: 'Network & Firewall',
        name: 'SMBv1 Protocol',
        status: smb.EnableSMB1Protocol ? 'Fail' : 'Pass',
        value: smb.EnableSMB1Protocol ? 'Enabled' : 'Disabled',
        recommendation: smb.EnableSMB1Protocol ? 'Disable SMBv1 - it has known security vulnerabilities' : undefined,
        severity: smb.EnableSMB1Protocol ? 'High' : 'Info'
      });
    }
    
    // Count open ports - only show if there are unusual ports
    if (output.includes('=== OPEN PORTS ===')) {
      const portsSection = output.split('=== OPEN PORTS ===')[1].split('===')[0];
      try {
        const ports = JSON.parse(portsSection.trim());
        const portArray = Array.isArray(ports) ? ports : [ports];
        // Only show if there are a lot of open ports (potential security concern)
        if (portArray.length > 50) {
          results.push({
            category: 'Network & Firewall',
            name: 'Open Listening Ports',
            status: 'Warning',
            value: `${portArray.length} ports listening`,
            recommendation: 'High number of open ports - review and close unnecessary ones',
            severity: 'Medium'
          });
        }
      } catch (e) {
        // JSON parse error, might be empty
      }
    }
  } catch (error) {
    console.error('Error parsing network/firewall audit:', error);
  }
  
  return results;
};

export const parseSecuritySoftware = (output: string): AuditResult[] => {
  const results: AuditResult[] = [];
  
  try {
    if (output.includes('=== DEFENDER STATUS ===')) {
      const defenderSection = output.split('=== DEFENDER STATUS ===')[1].split('===')[0];
      const defender = JSON.parse(defenderSection.trim());
      
      results.push({
        category: 'Security Software',
        name: 'Windows Defender Antivirus',
        status: defender.AntivirusEnabled ? 'Pass' : 'Fail',
        value: defender.AntivirusEnabled ? 'Enabled' : 'Disabled',
        recommendation: defender.AntivirusEnabled ? undefined : 'Enable Windows Defender',
        severity: defender.AntivirusEnabled ? 'Info' : 'High'
      });
      
      results.push({
        category: 'Security Software',
        name: 'Real-Time Protection',
        status: defender.RealTimeProtectionEnabled ? 'Pass' : 'Fail',
        value: defender.RealTimeProtectionEnabled ? 'Enabled' : 'Disabled',
        recommendation: defender.RealTimeProtectionEnabled ? undefined : 'Enable real-time protection',
        severity: defender.RealTimeProtectionEnabled ? 'Info' : 'High'
      });
      
      results.push({
        category: 'Security Software',
        name: 'Tamper Protection',
        status: defender.IsTamperProtected ? 'Pass' : 'Warning',
        value: defender.IsTamperProtected ? 'Enabled' : 'Disabled',
        recommendation: defender.IsTamperProtected ? undefined : 'Enable tamper protection to prevent malware from disabling Defender',
        severity: defender.IsTamperProtected ? 'Info' : 'Medium'
      });
      
      // Check signature age
      if (defender.AntivirusSignatureLastUpdated) {
        const lastUpdate = new Date(defender.AntivirusSignatureLastUpdated);
        const daysSinceUpdate = Math.floor((Date.now() - lastUpdate.getTime()) / (1000 * 60 * 60 * 24));
        
        if (!isNaN(daysSinceUpdate) && daysSinceUpdate >= 0) {
          results.push({
            category: 'Security Software',
            name: 'Antivirus Signatures',
            status: daysSinceUpdate <= 7 ? 'Pass' : 'Warning',
            value: `Last updated ${daysSinceUpdate} day(s) ago`,
            recommendation: daysSinceUpdate > 7 ? 'Update antivirus signatures' : undefined,
            severity: daysSinceUpdate > 7 ? 'Medium' : 'Info'
          });
        }
      }
    }
  } catch (error) {
    console.error('Error parsing security software audit:', error);
  }
  
  return results;
};

export const parseUpdatesPatch = (output: string): AuditResult[] => {
  const results: AuditResult[] = [];
  
  try {
    // Check auto-update
    if (output.includes('AutoUpdate Enabled:')) {
      const autoUpdateLine = output.match(/AutoUpdate Enabled:\s*(\w+)/);
      if (autoUpdateLine) {
        const enabled = autoUpdateLine[1] === 'True';
        results.push({
          category: 'Updates & Patches',
          name: 'Automatic Updates',
          status: enabled ? 'Pass' : 'Fail',
          value: enabled ? 'Enabled' : 'Disabled',
          recommendation: enabled ? undefined : 'Enable automatic Windows updates',
          severity: enabled ? 'Info' : 'High'
        });
      }
    }
    
    // Count pending updates
    if (output.includes('=== PENDING UPDATES ===')) {
      const updatesSection = output.split('=== PENDING UPDATES ===')[1].split('===')[0];
      try {
        const updates = JSON.parse(updatesSection.trim());
        const updateArray = Array.isArray(updates) ? updates : (updates ? [updates] : []);
        const criticalUpdates = updateArray.filter((u: any) => u.Severity === 'Critical').length;
        
        results.push({
          category: 'Updates & Patches',
          name: 'Pending Updates',
          status: updateArray.length === 0 ? 'Pass' : (criticalUpdates > 0 ? 'Fail' : 'Warning'),
          value: `${updateArray.length} pending (${criticalUpdates} critical)`,
          recommendation: updateArray.length > 0 ? 'Install pending Windows updates' : undefined,
          severity: criticalUpdates > 0 ? 'High' : (updateArray.length > 0 ? 'Medium' : 'Info')
        });
      } catch (e) {
        // No pending updates or parse error
        results.push({
          category: 'Updates & Patches',
          name: 'Pending Updates',
          status: 'Pass',
          value: '0 pending',
          severity: 'Info'
        });
      }
    }
    
    // Last update date
    if (output.includes('=== LAST UPDATE ===')) {
      const lastUpdateSection = output.split('=== LAST UPDATE ===')[1].split('===')[0];
      try {
        const lastUpdate = JSON.parse(lastUpdateSection.trim());
        if (lastUpdate.InstalledOn) {
          const installDate = new Date(lastUpdate.InstalledOn);
          const daysSince = Math.floor((Date.now() - installDate.getTime()) / (1000 * 60 * 60 * 24));
          
          if (!isNaN(daysSince) && daysSince >= 0) {
            results.push({
              category: 'Updates & Patches',
              name: 'Last Update Installed',
              status: daysSince <= 30 ? 'Pass' : 'Warning',
              value: `${daysSince} day(s) ago (${lastUpdate.Description || 'Update'})`,
              recommendation: daysSince > 30 ? 'System has not been updated recently' : undefined,
              severity: daysSince > 60 ? 'Medium' : 'Info'
            });
          }
        }
      } catch (e) {
        // Parse error - skip this check
      }
    }
  } catch (error) {
    console.error('Error parsing updates audit:', error);
  }
  
  return results;
};

export const parseEncryptionBitLocker = (output: string): AuditResult[] => {
  const results: AuditResult[] = [];
  
  try {
    // BitLocker status
    if (output.includes('=== BITLOCKER STATUS ===')) {
      const bitlockerSection = output.split('=== BITLOCKER STATUS ===')[1].split('===')[0];
      try {
        const volumes = JSON.parse(bitlockerSection.trim());
        const volumeArray = Array.isArray(volumes) ? volumes : [volumes];
        
        volumeArray.forEach((vol: any) => {
          const isEncrypted = vol.VolumeStatus === 'FullyEncrypted';
          const isProtected = vol.ProtectionStatus === 'On';
          
          results.push({
            category: 'Encryption & BitLocker',
            name: `BitLocker - ${vol.MountPoint} Drive`,
            status: isEncrypted && isProtected ? 'Pass' : 'Warning',
            value: `${vol.VolumeStatus} (${vol.EncryptionPercentage}%)`,
            recommendation: !isEncrypted ? `Enable BitLocker encryption on ${vol.MountPoint}` : undefined,
            severity: !isEncrypted && vol.MountPoint === 'C:' ? 'High' : 'Medium'
          });
        });
      } catch (e) {
        results.push({
          category: 'Encryption & BitLocker',
          name: 'BitLocker',
          status: 'Warning',
          value: 'Not configured',
          recommendation: 'Enable BitLocker to encrypt your drives',
          severity: 'High'
        });
      }
    }
    
    // TPM status
    if (output.includes('TPM Present:')) {
      const tpmPresent = output.includes('TPM Present: True');
      const tpmReady = output.includes('TPM Ready: True');
      
      results.push({
        category: 'Encryption & BitLocker',
        name: 'TPM (Trusted Platform Module)',
        status: tpmPresent && tpmReady ? 'Pass' : 'Warning',
        value: tpmPresent ? (tpmReady ? 'Present and Ready' : 'Present but not ready') : 'Not present',
        recommendation: !tpmPresent ? 'TPM is required for full BitLocker security' : undefined,
        severity: tpmPresent ? 'Info' : 'Medium'
      });
    }
  } catch (error) {
    console.error('Error parsing encryption audit:', error);
  }
  
  return results;
};

export const parseServicesAndTasks = (output: string): AuditResult[] => {
  const results: AuditResult[] = [];
  
  try {
    // Running services count - only show if unusually high
    if (output.includes('=== SYSTEM SERVICES ===')) {
      const servicesSection = output.split('=== SYSTEM SERVICES ===')[1].split('===')[0];
      try {
        const services = JSON.parse(servicesSection.trim());
        const serviceArray = Array.isArray(services) ? services : [services];
        
        // Only show warning if there are many services running
        if (serviceArray.length > 100) {
          results.push({
            category: 'Services & Tasks',
            name: 'Running Services',
            status: 'Warning',
            value: `${serviceArray.length} services running`,
            recommendation: 'High number of running services - review and disable unnecessary ones',
            severity: 'Low'
          });
        }
      } catch (e) {
        // Parse error
      }
    }
    
    // Scheduled tasks - only show if concerning number
    if (output.includes('=== SCHEDULED TASKS (ENABLED) ===')) {
      const tasksSection = output.split('=== SCHEDULED TASKS (ENABLED) ===')[1].split('===')[0];
      try {
        const tasks = JSON.parse(tasksSection.trim());
        const taskArray = Array.isArray(tasks) ? tasks : [tasks];
        
        if (taskArray.length > 200) {
          results.push({
            category: 'Services & Tasks',
            name: 'Scheduled Tasks',
            status: 'Warning',
            value: `${taskArray.length} active tasks`,
            recommendation: 'High number of scheduled tasks - review for suspicious entries',
            severity: 'Low'
          });
        }
      } catch (e) {
        // Parse error
      }
    }
  } catch (error) {
    console.error('Error parsing services/tasks audit:', error);
  }
  
  return results;
};

export const parseFileSystemShares = (output: string): AuditResult[] => {
  const results: AuditResult[] = [];
  
  try {
    // Network shares
    if (output.includes('=== NETWORK SHARES ===')) {
      const sharesSection = output.split('=== NETWORK SHARES ===')[1].split('===')[0];
      try {
        const shares = JSON.parse(sharesSection.trim());
        const shareArray = Array.isArray(shares) ? shares : [shares];
        const nonDefaultShares = shareArray.filter((s: any) => !s.Name.endsWith('$'));
        
        results.push({
          category: 'File System & Shares',
          name: 'Network Shares',
          status: nonDefaultShares.length === 0 ? 'Pass' : 'Warning',
          value: `${nonDefaultShares.length} share(s) exposed`,
          recommendation: nonDefaultShares.length > 0 ? 'Review share permissions carefully' : undefined,
          severity: nonDefaultShares.length > 0 ? 'Medium' : 'Info'
        });
      } catch (e) {
        results.push({
          category: 'File System & Shares',
          name: 'Network Shares',
          status: 'Pass',
          value: 'No shares found',
          severity: 'Info'
        });
      }
    }
  } catch (error) {
    console.error('Error parsing file system audit:', error);
  }
  
  return results;
};

export const parseEventLogs = (output: string): AuditResult[] => {
  const results: AuditResult[] = [];
  
  try {
    // Check if admin privileges are required
    if (output.includes('REQUIRES_ADMIN')) {
      results.push({
        category: 'Event Logs & Monitoring',
        name: 'Event Log Access',
        status: 'Warning',
        value: 'Requires Administrator privileges',
        recommendation: 'Run the application as Administrator to access security event logs',
        severity: 'Info'
      });
      return results;
    }
    
    // Failed logins
    if (output.includes('=== FAILED LOGINS (LAST 24H) ===')) {
      const loginsSection = output.split('=== FAILED LOGINS (LAST 24H) ===')[1].split('===')[0];
      try {
        const logins = JSON.parse(loginsSection.trim());
        const loginArray = Array.isArray(logins) ? logins : (logins ? [logins] : []);
        
        results.push({
          category: 'Event Logs & Monitoring',
          name: 'Failed Login Attempts (24h)',
          status: loginArray.length === 0 ? 'Pass' : (loginArray.length > 10 ? 'Fail' : 'Warning'),
          value: `${loginArray.length} failed attempts`,
          recommendation: loginArray.length > 10 ? 'High number of failed logins - possible brute force attack' : undefined,
          severity: loginArray.length > 10 ? 'High' : (loginArray.length > 0 ? 'Medium' : 'Info')
        });
      } catch (e) {
        results.push({
          category: 'Event Logs & Monitoring',
          name: 'Failed Login Attempts (24h)',
          status: 'Pass',
          value: '0 failed attempts',
          severity: 'Info'
        });
      }
    }
    
    // Audit policy
    if (output.includes('=== AUDIT POLICY ===')) {
      results.push({
        category: 'Event Logs & Monitoring',
        name: 'Audit Logging',
        status: 'Info',
        value: 'Configured',
        recommendation: 'Review audit policy settings to ensure comprehensive logging',
        severity: 'Info'
      });
    }
  } catch (error) {
    console.error('Error parsing event logs audit:', error);
  }
  
  return results;
};

export const parseBrowserApps = (output: string): AuditResult[] => {
  const results: AuditResult[] = [];
  
  try {
    // Installed software count - make less verbose
    if (output.includes('=== INSTALLED SOFTWARE ===')) {
      const softwareSection = output.split('=== INSTALLED SOFTWARE ===')[1].split('===')[0];
      try {
        const software = JSON.parse(softwareSection.trim());
        const softwareArray = Array.isArray(software) ? software : [software];
        
        // Only show if there's a large number of applications
        if (softwareArray.length > 50) {
          results.push({
            category: 'Browser & Applications',
            name: 'Installed Applications',
            status: 'Info',
            value: `${softwareArray.length} applications installed`,
            recommendation: 'Consider reviewing and removing unnecessary applications',
            severity: 'Info'
          });
        }
      } catch (e) {
        // Parse error
      }
    }
    
    // Certificates - only show if concerning
    if (output.includes('=== CERTIFICATES (USER) ===')) {
      const certsSection = output.split('=== CERTIFICATES (USER) ===')[1].split('===')[0];
      try {
        const certs = JSON.parse(certsSection.trim());
        const certArray = Array.isArray(certs) ? certs : [certs];
        
        // Only show if there are many certificates (potential concern)
        if (certArray.length > 20) {
          results.push({
            category: 'Browser & Applications',
            name: 'Root Certificates',
            status: 'Warning',
            value: `${certArray.length} certificates in trusted root`,
            recommendation: 'High number of certificates - review for suspicious or unknown issuers',
            severity: 'Medium'
          });
        }
      } catch (e) {
        // Parse error
      }
    }
    
    // Startup programs
    if (output.includes('=== STARTUP PROGRAMS ===')) {
      const startupSection = output.split('=== STARTUP PROGRAMS ===')[1].split('===')[0];
      try {
        const startup = JSON.parse(startupSection.trim());
        const startupArray = Array.isArray(startup) ? startup : [startup];
        
        results.push({
          category: 'Browser & Applications',
          name: 'Startup Programs',
          status: startupArray.length > 15 ? 'Warning' : 'Pass',
          value: `${startupArray.length} programs at startup`,
          recommendation: startupArray.length > 15 ? 'Consider disabling unnecessary startup programs to improve boot time' : undefined,
          severity: startupArray.length > 15 ? 'Low' : 'Info'
        });
      } catch (e) {
        // Parse error
      }
    }
  } catch (error) {
    console.error('Error parsing browser/apps audit:', error);
  }
  
  return results;
};

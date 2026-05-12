# ============================================
# Script: Invoke-AzSecurityAssessment.ps1
# Purpose: Main Azure Security Assessment
#          Tool — scans 50+ security controls
#          and generates HTML report
# Author: Uzma Shabbir
# Version: 1.0
# Date: April 2026
# ============================================

param(
    [string]$SubscriptionId = "",
    [string]$OutputPath = ".\reports",
    [switch]$OpenReport = $true
)

# ============================================
# INITIALIZATION
# ============================================

Write-Host @"
╔════════════════════════════════════════════╗
║     Azure Security Assessment Tool        ║
║     Author: Uzma Sami                     ║
║     Version: 1.0 | April 2026             ║
║     AZ-104 | AZ-500                       ║
╚════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Connect to Azure
Connect-AzAccount -ErrorAction Stop

# Set subscription if provided
if ($SubscriptionId) {
    Set-AzContext -SubscriptionId $SubscriptionId
}

$context        = Get-AzContext
$subId          = $context.Subscription.Id
$subName        = $context.Subscription.Name
$tenantId       = $context.Tenant.Id
$reportDate     = Get-Date -Format "yyyy-MM-dd HH:mm"
$reportFileName = "AzSecurityReport-$(Get-Date -Format 'yyyyMMdd-HHmm').html"

# Create reports folder
New-Item -ItemType Directory `
    -Path $OutputPath `
    -Force | Out-Null

Write-Host "`n✅ Connected to: $subName" -ForegroundColor Green
Write-Host "Subscription ID: $subId" -ForegroundColor Cyan
Write-Host "`nStarting security assessment..." -ForegroundColor Yellow
Write-Host "Checking 50+ security controls..." -ForegroundColor Yellow

# ============================================
# FINDINGS COLLECTOR
# ============================================

$findings = @()
$passedCount   = 0
$failedCount   = 0
$warningCount  = 0

function Add-Finding {
    param(
        [string]$Category,
        [string]$Control,
        [string]$Status,      # PASS, FAIL, WARN
        [string]$Severity,    # Critical, High, Medium, Low
        [string]$Resource,
        [string]$Description,
        [string]$Remediation
    )

    $script:findings += [PSCustomObject]@{
        Category    = $Category
        Control     = $Control
        Status      = $Status
        Severity    = $Severity
        Resource    = $Resource
        Description = $Description
        Remediation = $Remediation
        CheckedAt   = Get-Date -Format "HH:mm:ss"
    }

    switch ($Status) {
        "PASS" {
            $script:passedCount++
            Write-Host "  ✅ PASS: $Control" `
                -ForegroundColor Green
        }
        "FAIL" {
            $script:failedCount++
            Write-Host "  ❌ FAIL [$Severity]: $Control" `
                -ForegroundColor Red
        }
        "WARN" {
            $script:warningCount++
            Write-Host "  ⚠️  WARN: $Control" `
                -ForegroundColor Yellow
        }
    }
}

# ============================================
# CATEGORY 1: IDENTITY & ACCESS MANAGEMENT
# ============================================

Write-Host "`n[1/6] Checking Identity & Access..." `
    -ForegroundColor Cyan

# Check 1.1: MFA for Global Admins
try {
    $globalAdminRole = Get-MgDirectoryRole `
        -Filter "DisplayName eq 'Global Administrator'" `
        -ErrorAction SilentlyContinue

    if ($globalAdminRole) {
        $globalAdmins = Get-MgDirectoryRoleMember `
            -DirectoryRoleId $globalAdminRole.Id `
            -ErrorAction SilentlyContinue

        $adminCount = ($globalAdmins | Measure-Object).Count

        if ($adminCount -le 3) {
            Add-Finding `
                -Category "Identity & Access" `
                -Control "Global Admin Count" `
                -Status "PASS" `
                -Severity "High" `
                -Resource "Azure AD" `
                -Description "Global Admin count is $adminCount (recommended: 2-3)" `
                -Remediation "Maintain 2-3 Global Admins maximum"
        } else {
            Add-Finding `
                -Category "Identity & Access" `
                -Control "Global Admin Count" `
                -Status "FAIL" `
                -Severity "High" `
                -Resource "Azure AD" `
                -Description "Too many Global Admins: $adminCount (recommended: 2-3 maximum)" `
                -Remediation "Review and reduce Global Admin assignments. Use specific roles instead of Global Admin where possible."
        }
    }
} catch {
    Write-Host "  ⚠️  Could not check Global Admins" `
        -ForegroundColor Yellow
}

# Check 1.2: Guest Users
try {
    $guestUsers = Get-AzADUser `
        -Filter "userType eq 'Guest'" `
        -ErrorAction SilentlyContinue

    $guestCount = ($guestUsers | Measure-Object).Count

    if ($guestCount -eq 0) {
        Add-Finding `
            -Category "Identity & Access" `
            -Control "Guest User Accounts" `
            -Status "PASS" `
            -Severity "Medium" `
            -Resource "Azure AD" `
            -Description "No guest users found" `
            -Remediation "No action required"
    } elseif ($guestCount -le 5) {
        Add-Finding `
            -Category "Identity & Access" `
            -Control "Guest User Accounts" `
            -Status "WARN" `
            -Severity "Medium" `
            -Resource "Azure AD" `
            -Description "$guestCount guest users found — review access" `
            -Remediation "Review all guest user access. Remove unnecessary guest accounts. Apply least privilege."
    } else {
        Add-Finding `
            -Category "Identity & Access" `
            -Control "Guest User Accounts" `
            -Status "FAIL" `
            -Severity "High" `
            -Resource "Azure AD" `
            -Description "$guestCount guest users found — excessive guest access" `
            -Remediation "Immediately review all guest accounts. Remove unused accounts. Implement guest access review policy."
    }
} catch {
    Write-Host "  ⚠️  Could not check guest users" `
        -ForegroundColor Yellow
}

# Check 1.3: Conditional Access Policies
try {
    $caPolicies = Get-MgIdentityConditionalAccessPolicy `
        -ErrorAction SilentlyContinue

    $enabledPolicies = $caPolicies |
        Where-Object {$_.State -eq "enabled"}

    if ($enabledPolicies.Count -ge 3) {
        Add-Finding `
            -Category "Identity & Access" `
            -Control "Conditional Access Policies" `
            -Status "PASS" `
            -Severity "Critical" `
            -Resource "Azure AD" `
            -Description "$($enabledPolicies.Count) Conditional Access policies enabled" `
            -Remediation "No action required"
    } elseif ($enabledPolicies.Count -gt 0) {
        Add-Finding `
            -Category "Identity & Access" `
            -Control "Conditional Access Policies" `
            -Status "WARN" `
            -Severity "Critical" `
            -Resource "Azure AD" `
            -Description "Only $($enabledPolicies.Count) CA policies — more recommended" `
            -Remediation "Add CA policies for MFA enforcement, legacy auth blocking, and risky sign-in response."
    } else {
        Add-Finding `
            -Category "Identity & Access" `
            -Control "Conditional Access Policies" `
            -Status "FAIL" `
            -Severity "Critical" `
            -Resource "Azure AD" `
            -Description "No Conditional Access policies found!" `
            -Remediation "Immediately create CA policies: Require MFA for admins, Block legacy auth, Block risky sign-ins."
    }
} catch {
    Write-Host "  ⚠️  Could not check CA policies" `
        -ForegroundColor Yellow
}

# Check 1.4: Service Principals with secrets
try {
    $spWithSecrets = Get-AzADServicePrincipal `
        -ErrorAction SilentlyContinue |
        Where-Object {$_.PasswordCredentials.Count -gt 0}

    $expiredSecrets = $spWithSecrets |
        Where-Object {
            $_.PasswordCredentials |
            Where-Object {$_.EndDateTime -lt (Get-Date)}
        }

    if ($expiredSecrets.Count -eq 0) {
        Add-Finding `
            -Category "Identity & Access" `
            -Control "Service Principal Secrets" `
            -Status "PASS" `
            -Severity "High" `
            -Resource "Azure AD" `
            -Description "No expired service principal secrets found" `
            -Remediation "Continue monitoring secret expiry dates"
    } else {
        Add-Finding `
            -Category "Identity & Access" `
            -Control "Service Principal Secrets" `
            -Status "FAIL" `
            -Severity "High" `
            -Resource "Azure AD" `
            -Description "$($expiredSecrets.Count) service principals have EXPIRED secrets" `
            -Remediation "Rotate expired secrets immediately. Implement secret rotation automation via Key Vault."
    }
} catch {
    Write-Host "  ⚠️  Could not check SP secrets" `
        -ForegroundColor Yellow
}

# ============================================
# CATEGORY 2: NETWORK SECURITY
# ============================================

Write-Host "`n[2/6] Checking Network Security..." `
    -ForegroundColor Cyan

# Check 2.1: NSGs on all subnets
try {
    $vnets   = Get-AzVirtualNetwork
    $subnets = $vnets | ForEach-Object {$_.Subnets}

    $subnetsWithoutNSG = $subnets |
        Where-Object {
            $_.NetworkSecurityGroup -eq $null -and
            $_.Name -notmatch "Gateway|Bastion|Firewall"
        }

    if ($subnetsWithoutNSG.Count -eq 0) {
        Add-Finding `
            -Category "Network Security" `
            -Control "NSG Coverage" `
            -Status "PASS" `
            -Severity "High" `
            -Resource "Virtual Networks" `
            -Description "All subnets have NSGs applied" `
            -Remediation "No action required"
    } else {
        Add-Finding `
            -Category "Network Security" `
            -Control "NSG Coverage" `
            -Status "FAIL" `
            -Severity "High" `
            -Resource "Virtual Networks" `
            -Description "$($subnetsWithoutNSG.Count) subnets without NSG protection" `
            -Remediation "Apply NSGs to all subnets. Use deny-all inbound as baseline rule."
    }
} catch {
    Write-Host "  ⚠️  Could not check NSGs" `
        -ForegroundColor Yellow
}

# Check 2.2: RDP/SSH open to internet
try {
    $nsgs = Get-AzNetworkSecurityGroup
    $openRDP = @()
    $openSSH = @()

    foreach ($nsg in $nsgs) {
        $rdpRules = $nsg.SecurityRules |
            Where-Object {
                $_.DestinationPortRange -contains "3389" -and
                $_.SourceAddressPrefix -eq "*" -and
                $_.Access -eq "Allow" -and
                $_.Direction -eq "Inbound"
            }

        $sshRules = $nsg.SecurityRules |
            Where-Object {
                $_.DestinationPortRange -contains "22" -and
                $_.SourceAddressPrefix -eq "*" -and
                $_.Access -eq "Allow" -and
                $_.Direction -eq "Inbound"
            }

        if ($rdpRules) {$openRDP += $nsg.Name}
        if ($sshRules) {$openSSH += $nsg.Name}
    }

    if ($openRDP.Count -eq 0) {
        Add-Finding `
            -Category "Network Security" `
            -Control "RDP Open to Internet" `
            -Status "PASS" `
            -Severity "Critical" `
            -Resource "NSGs" `
            -Description "No NSGs allow RDP from internet" `
            -Remediation "No action required"
    } else {
        Add-Finding `
            -Category "Network Security" `
            -Control "RDP Open to Internet" `
            -Status "FAIL" `
            -Severity "Critical" `
            -Resource ($openRDP -join ", ") `
            -Description "RDP port 3389 open to internet on: $($openRDP -join ', ')" `
            -Remediation "URGENT: Remove RDP internet access immediately. Use Azure Bastion or VPN for remote access."
    }

    if ($openSSH.Count -eq 0) {
        Add-Finding `
            -Category "Network Security" `
            -Control "SSH Open to Internet" `
            -Status "PASS" `
            -Severity "Critical" `
            -Resource "NSGs" `
            -Description "No NSGs allow SSH from internet" `
            -Remediation "No action required"
    } else {
        Add-Finding `
            -Category "Network Security" `
            -Control "SSH Open to Internet" `
            -Status "FAIL" `
            -Severity "Critical" `
            -Resource ($openSSH -join ", ") `
            -Description "SSH port 22 open to internet on: $($openSSH -join ', ')" `
            -Remediation "URGENT: Remove SSH internet access. Use Azure Bastion or VPN instead."
    }
} catch {
    Write-Host "  ⚠️  Could not check RDP/SSH rules" `
        -ForegroundColor Yellow
}

# Check 2.3: Public IP addresses
try {
    $publicIPs = Get-AzPublicIpAddress
    $unusedIPs = $publicIPs |
        Where-Object {$_.IpConfiguration -eq $null}

    if ($unusedIPs.Count -eq 0) {
        Add-Finding `
            -Category "Network Security" `
            -Control "Unused Public IPs" `
            -Status "PASS" `
            -Severity "Low" `
            -Resource "Public IPs" `
            -Description "No unused public IP addresses found" `
            -Remediation "No action required"
    } else {
        Add-Finding `
            -Category "Network Security" `
            -Control "Unused Public IPs" `
            -Status "WARN" `
            -Severity "Low" `
            -Resource "Public IPs" `
            -Description "$($unusedIPs.Count) unused public IPs consuming cost" `
            -Remediation "Delete unused public IP addresses to reduce cost and attack surface."
    }
} catch {
    Write-Host "  ⚠️  Could not check public IPs" `
        -ForegroundColor Yellow
}

# Check 2.4: DDoS Protection
try {
    $vnets = Get-AzVirtualNetwork
    $vnetsWithoutDDoS = $vnets |
        Where-Object {
            $_.DdosProtectionPlan -eq $null
        }

    if ($vnetsWithoutDDoS.Count -eq 0) {
        Add-Finding `
            -Category "Network Security" `
            -Control "DDoS Protection" `
            -Status "PASS" `
            -Severity "Medium" `
            -Resource "Virtual Networks" `
            -Description "DDoS protection enabled on all VNets" `
            -Remediation "No action required"
    } else {
        Add-Finding `
            -Category "Network Security" `
            -Control "DDoS Protection" `
            -Status "WARN" `
            -Severity "Medium" `
            -Resource "Virtual Networks" `
            -Description "$($vnetsWithoutDDoS.Count) VNets without DDoS Standard protection" `
            -Remediation "Consider enabling DDoS Standard for production workloads. DDoS Basic is enabled by default."
    }
} catch {
    Write-Host "  ⚠️  Could not check DDoS" `
        -ForegroundColor Yellow
}

# ============================================
# CATEGORY 3: DATA SECURITY
# ============================================

Write-Host "`n[3/6] Checking Data Security..." `
    -ForegroundColor Cyan

# Check 3.1: Storage Account HTTPS
try {
    $storageAccounts = Get-AzStorageAccount
    $httpStorage = $storageAccounts |
        Where-Object {
            $_.EnableHttpsTrafficOnly -eq $false
        }

    if ($httpStorage.Count -eq 0) {
        Add-Finding `
            -Category "Data Security" `
            -Control "Storage HTTPS Only" `
            -Status "PASS" `
            -Severity "High" `
            -Resource "Storage Accounts" `
            -Description "All storage accounts enforce HTTPS" `
            -Remediation "No action required"
    } else {
        Add-Finding `
            -Category "Data Security" `
            -Control "Storage HTTPS Only" `
            -Status "FAIL" `
            -Severity "High" `
            -Resource "Storage Accounts" `
            -Description "$($httpStorage.Count) storage accounts allow HTTP traffic" `
            -Remediation "Enable HTTPS-only traffic on all storage accounts immediately."
    }
} catch {
    Write-Host "  ⚠️  Could not check storage HTTPS" `
        -ForegroundColor Yellow
}

# Check 3.2: Storage Public Access
try {
    $publicStorage = $storageAccounts |
        Where-Object {
            $_.AllowBlobPublicAccess -eq $true
        }

    if ($publicStorage.Count -eq 0) {
        Add-Finding `
            -Category "Data Security" `
            -Control "Storage Public Access" `
            -Status "PASS" `
            -Severity "Critical" `
            -Resource "Storage Accounts" `
            -Description "No storage accounts allow public blob access" `
            -Remediation "No action required"
    } else {
        Add-Finding `
            -Category "Data Security" `
            -Control "Storage Public Access" `
            -Status "FAIL" `
            -Severity "Critical" `
            -Resource "Storage Accounts" `
            -Description "$($publicStorage.Count) storage accounts allow public blob access!" `
            -Remediation "URGENT: Disable public blob access on all storage accounts unless explicitly required."
    }
} catch {
    Write-Host "  ⚠️  Could not check storage public access" `
        -ForegroundColor Yellow
}

# Check 3.3: Storage Minimum TLS
try {
    $oldTLSStorage = $storageAccounts |
        Where-Object {
            $_.MinimumTlsVersion -ne "TLS1_2"
        }

    if ($oldTLSStorage.Count -eq 0) {
        Add-Finding `
            -Category "Data Security" `
            -Control "Storage TLS Version" `
            -Status "PASS" `
            -Severity "High" `
            -Resource "Storage Accounts" `
            -Description "All storage accounts enforce TLS 1.2" `
            -Remediation "No action required"
    } else {
        Add-Finding `
            -Category "Data Security" `
            -Control "Storage TLS Version" `
            -Status "FAIL" `
            -Severity "High" `
            -Resource "Storage Accounts" `
            -Description "$($oldTLSStorage.Count) storage accounts using TLS below 1.2" `
            -Remediation "Set minimum TLS version to 1.2 on all storage accounts."
    }
} catch {
    Write-Host "  ⚠️  Could not check TLS version" `
        -ForegroundColor Yellow
}

# Check 3.4: Key Vault Soft Delete
try {
    $keyVaults = Get-AzKeyVault
    $noSoftDelete = $keyVaults |
        Where-Object {
            $_.EnableSoftDelete -eq $false -or
            $_.EnableSoftDelete -eq $null
        }

    if ($keyVaults.Count -eq 0) {
        Add-Finding `
            -Category "Data Security" `
            -Control "Key Vault Soft Delete" `
            -Status "WARN" `
            -Severity "Medium" `
            -Resource "Key Vault" `
            -Description "No Key Vaults found" `
            -Remediation "Consider using Key Vault for secrets management"
    } elseif ($noSoftDelete.Count -eq 0) {
        Add-Finding `
            -Category "Data Security" `
            -Control "Key Vault Soft Delete" `
            -Status "PASS" `
            -Severity "High" `
            -Resource "Key Vault" `
            -Description "All Key Vaults have soft delete enabled" `
            -Remediation "No action required"
    } else {
        Add-Finding `
            -Category "Data Security" `
            -Control "Key Vault Soft Delete" `
            -Status "FAIL" `
            -Severity "High" `
            -Resource "Key Vault" `
            -Description "$($noSoftDelete.Count) Key Vaults without soft delete" `
            -Remediation "Enable soft delete and purge protection on all Key Vaults immediately."
    }
} catch {
    Write-Host "  ⚠️  Could not check Key Vaults" `
        -ForegroundColor Yellow
}

# Check 3.5: SQL Server TLS
try {
    $sqlServers = Get-AzSqlServer `
        -ErrorAction SilentlyContinue

    if ($sqlServers.Count -eq 0) {
        Add-Finding `
            -Category "Data Security" `
            -Control "SQL Server TLS" `
            -Status "WARN" `
            -Severity "Medium" `
            -Resource "SQL Server" `
            -Description "No SQL Servers found" `
            -Remediation "No action required"
    } else {
        $oldTLSSQL = $sqlServers |
            Where-Object {
                $_.MinimalTlsVersion -ne "1.2"
            }

        if ($oldTLSSQL.Count -eq 0) {
            Add-Finding `
                -Category "Data Security" `
                -Control "SQL Server TLS" `
                -Status "PASS" `
                -Severity "High" `
                -Resource "SQL Servers" `
                -Description "All SQL Servers enforce TLS 1.2" `
                -Remediation "No action required"
        } else {
            Add-Finding `
                -Category "Data Security" `
                -Control "SQL Server TLS" `
                -Status "FAIL" `
                -Severity "High" `
                -Resource "SQL Servers" `
                -Description "$($oldTLSSQL.Count) SQL Servers not enforcing TLS 1.2" `
                -Remediation "Set minimum TLS version to 1.2 on all SQL Servers."
        }
    }
} catch {
    Write-Host "  ⚠️  Could not check SQL TLS" `
        -ForegroundColor Yellow
}

# ============================================
# CATEGORY 4: LOGGING & MONITORING
# ============================================

Write-Host "`n[4/6] Checking Logging & Monitoring..." `
    -ForegroundColor Cyan

# Check 4.1: Log Analytics Workspace exists
try {
    $workspaces = Get-AzOperationalInsightsWorkspace

    if ($workspaces.Count -gt 0) {
        Add-Finding `
            -Category "Logging & Monitoring" `
            -Control "Log Analytics Workspace" `
            -Status "PASS" `
            -Severity "High" `
            -Resource "Log Analytics" `
            -Description "$($workspaces.Count) Log Analytics workspace(s) found" `
            -Remediation "No action required"
    } else {
        Add-Finding `
            -Category "Logging & Monitoring" `
            -Control "Log Analytics Workspace" `
            -Status "FAIL" `
            -Severity "High" `
            -Resource "Log Analytics" `
            -Description "No Log Analytics workspace found" `
            -Remediation "Create a Log Analytics workspace and connect all resources for centralized monitoring."
    }
} catch {
    Write-Host "  ⚠️  Could not check workspaces" `
        -ForegroundColor Yellow
}

# Check 4.2: Microsoft Sentinel enabled
try {
    $sentinelEnabled = $false
    foreach ($ws in $workspaces) {
        $sentinel = Get-AzSentinelOnboardingState `
            -ResourceGroupName $ws.ResourceGroupName `
            -WorkspaceName $ws.Name `
            -Name "default" `
            -ErrorAction SilentlyContinue

        if ($sentinel) {
            $sentinelEnabled = $true
            break
        }
    }

    if ($sentinelEnabled) {
        Add-Finding `
            -Category "Logging & Monitoring" `
            -Control "Microsoft Sentinel" `
            -Status "PASS" `
            -Severity "High" `
            -Resource "Sentinel" `
            -Description "Microsoft Sentinel is enabled and active" `
            -Remediation "No action required"
    } else {
        Add-Finding `
            -Category "Logging & Monitoring" `
            -Control "Microsoft Sentinel" `
            -Status "FAIL" `
            -Severity "High" `
            -Resource "Sentinel" `
            -Description "Microsoft Sentinel not enabled" `
            -Remediation "Enable Microsoft Sentinel on your Log Analytics workspace for SIEM capabilities."
    }
} catch {
    Write-Host "  ⚠️  Could not check Sentinel" `
        -ForegroundColor Yellow
}

# Check 4.3: Network Watcher
try {
    $networkWatchers = Get-AzNetworkWatcher `
        -ErrorAction SilentlyContinue

    if ($networkWatchers.Count -gt 0) {
        Add-Finding `
            -Category "Logging & Monitoring" `
            -Control "Network Watcher" `
            -Status "PASS" `
            -Severity "Medium" `
            -Resource "Network Watcher" `
            -Description "Network Watcher enabled in $($networkWatchers.Count) region(s)" `
            -Remediation "No action required"
    } else {
        Add-Finding `
            -Category "Logging & Monitoring" `
            -Control "Network Watcher" `
            -Status "FAIL" `
            -Severity "Medium" `
            -Resource "Network Watcher" `
            -Description "Network Watcher not enabled" `
            -Remediation "Enable Network Watcher in all regions where you have resources."
    }
} catch {
    Write-Host "  ⚠️  Could not check Network Watcher" `
        -ForegroundColor Yellow
}

# Check 4.4: Diagnostic Settings on Key Resources
try {
    $kvs = Get-AzKeyVault -ErrorAction SilentlyContinue
    $kvWithDiag = 0

    foreach ($kv in $kvs) {
        $kvResource = Get-AzResource `
            -ResourceName $kv.VaultName `
            -ResourceType "Microsoft.KeyVault/vaults"

        $diagSettings = Get-AzDiagnosticSetting `
            -ResourceId $kvResource.ResourceId `
            -ErrorAction SilentlyContinue

        if ($diagSettings) {$kvWithDiag++}
    }

    if ($kvs.Count -eq 0) {
        Add-Finding `
            -Category "Logging & Monitoring" `
            -Control "Key Vault Diagnostics" `
            -Status "WARN" `
            -Severity "Medium" `
            -Resource "Key Vault" `
            -Description "No Key Vaults to check" `
            -Remediation "No action required"
    } elseif ($kvWithDiag -eq $kvs.Count) {
        Add-Finding `
            -Category "Logging & Monitoring" `
            -Control "Key Vault Diagnostics" `
            -Status "PASS" `
            -Severity "High" `
            -Resource "Key Vault" `
            -Description "All Key Vaults have diagnostic logging enabled" `
            -Remediation "No action required"
    } else {
        Add-Finding `
            -Category "Logging & Monitoring" `
            -Control "Key Vault Diagnostics" `
            -Status "FAIL" `
            -Severity "High" `
            -Resource "Key Vault" `
            -Description "$($kvs.Count - $kvWithDiag) Key Vaults missing diagnostic logging" `
            -Remediation "Enable diagnostic settings on all Key Vaults to log access and operations."
    }
} catch {
    Write-Host "  ⚠️  Could not check KV diagnostics" `
        -ForegroundColor Yellow
}

# ============================================
# CATEGORY 5: DEFENDER FOR CLOUD
# ============================================

Write-Host "`n[5/6] Checking Defender for Cloud..." `
    -ForegroundColor Cyan

# Check 5.1: Defender Plans
try {
    $defenderPlans = Get-AzSecurityPricing

    $standardPlans = $defenderPlans |
        Where-Object {$_.PricingTier -eq "Standard"}

    $freePlans = $defenderPlans |
        Where-Object {$_.PricingTier -eq "Free"}

    if ($standardPlans.Count -ge 3) {
        Add-Finding `
            -Category "Defender for Cloud" `
            -Control "Defender Plans Enabled" `
            -Status "PASS" `
            -Severity "High" `
            -Resource "Defender for Cloud" `
            -Description "$($standardPlans.Count) Defender plans on Standard tier" `
            -Remediation "No action required"
    } elseif ($standardPlans.Count -gt 0) {
        Add-Finding `
            -Category "Defender for Cloud" `
            -Control "Defender Plans Enabled" `
            -Status "WARN" `
            -Severity "High" `
            -Resource "Defender for Cloud" `
            -Description "Only $($standardPlans.Count) Defender plans enabled" `
            -Remediation "Enable Defender plans for Servers, SQL, Storage, and Key Vault."
    } else {
        Add-Finding `
            -Category "Defender for Cloud" `
            -Control "Defender Plans Enabled" `
            -Status "FAIL" `
            -Severity "Critical" `
            -Resource "Defender for Cloud" `
            -Description "No Defender Standard plans enabled!" `
            -Remediation "Enable Microsoft Defender for Cloud Standard tier for comprehensive threat protection."
    }
} catch {
    Write-Host "  ⚠️  Could not check Defender plans" `
        -ForegroundColor Yellow
}

# Check 5.2: Security Contacts
try {
    $secContacts = Get-AzSecurityContact `
        -ErrorAction SilentlyContinue

    if ($secContacts.Count -gt 0) {
        Add-Finding `
            -Category "Defender for Cloud" `
            -Control "Security Contacts" `
            -Status "PASS" `
            -Severity "Medium" `
            -Resource "Defender for Cloud" `
            -Description "Security contacts configured" `
            -Remediation "No action required"
    } else {
        Add-Finding `
            -Category "Defender for Cloud" `
            -Control "Security Contacts" `
            -Status "FAIL" `
            -Severity "Medium" `
            -Resource "Defender for Cloud" `
            -Description "No security contacts configured" `
            -Remediation "Add security contact email in Defender for Cloud settings for alert notifications."
    }
} catch {
    Write-Host "  ⚠️  Could not check security contacts" `
        -ForegroundColor Yellow
}

# Check 5.3: Secure Score
try {
    $secureScore = Get-AzSecuritySecureScore `
        -ErrorAction SilentlyContinue |
        Where-Object {$_.Name -eq "ascScore"} |
        Select-Object -First 1

    if ($secureScore) {
        $score = [math]::Round(
            $secureScore.PercentageFull * 100, 0
        )

        $scoreStatus = switch ($score) {
            {$_ -ge 70} {"PASS"}
            {$_ -ge 50} {"WARN"}
            default     {"FAIL"}
        }

        $scoreSeverity = switch ($score) {
            {$_ -ge 70} {"Low"}
            {$_ -ge 50} {"Medium"}
            default     {"High"}
        }

        Add-Finding `
            -Category "Defender for Cloud" `
            -Control "Secure Score" `
            -Status $scoreStatus `
            -Severity $scoreSeverity `
            -Resource "Defender for Cloud" `
            -Description "Current Secure Score: $score%" `
            -Remediation "Target 70%+ secure score. Implement recommended controls in Defender for Cloud."
    }
} catch {
    Write-Host "  ⚠️  Could not check Secure Score" `
        -ForegroundColor Yellow
}

# ============================================
# CATEGORY 6: GOVERNANCE & COMPLIANCE
# ============================================

Write-Host "`n[6/6] Checking Governance..." `
    -ForegroundColor Cyan

# Check 6.1: Resource Locks on critical resources
try {
    $locks = Get-AzResourceLock -ErrorAction SilentlyContinue

    if ($locks.Count -gt 0) {
        Add-Finding `
            -Category "Governance" `
            -Control "Resource Locks" `
            -Status "PASS" `
            -Severity "Medium" `
            -Resource "Resource Locks" `
            -Description "$($locks.Count) resource locks configured" `
            -Remediation "No action required"
    } else {
        Add-Finding `
            -Category "Governance" `
            -Control "Resource Locks" `
            -Status "WARN" `
            -Severity "Medium" `
            -Resource "Resource Locks" `
            -Description "No resource locks found" `
            -Remediation "Apply CanNotDelete locks on critical resources like Key Vaults, Log Analytics, and VNets."
    }
} catch {
    Write-Host "  ⚠️  Could not check resource locks" `
        -ForegroundColor Yellow
}

# Check 6.2: Tags on resources
try {
    $allResources = Get-AzResource
    $untagged = $allResources |
        Where-Object {
            $_.Tags -eq $null -or
            $_.Tags.Count -eq 0
        }

    $tagCoverage = [math]::Round(
        (($allResources.Count - $untagged.Count) /
        $allResources.Count) * 100, 0
    )

    if ($tagCoverage -ge 80) {
        Add-Finding `
            -Category "Governance" `
            -Control "Resource Tagging" `
            -Status "PASS" `
            -Severity "Low" `
            -Resource "All Resources" `
            -Description "Tag coverage: $tagCoverage% ($($untagged.Count) untagged)" `
            -Remediation "No action required"
    } elseif ($tagCoverage -ge 50) {
        Add-Finding `
            -Category "Governance" `
            -Control "Resource Tagging" `
            -Status "WARN" `
            -Severity "Low" `
            -Resource "All Resources" `
            -Description "Tag coverage: $tagCoverage% — $($untagged.Count) resources untagged" `
            -Remediation "Implement tagging policy. Tag all resources with Environment, Owner, CostCenter."
    } else {
        Add-Finding `
            -Category "Governance" `
            -Control "Resource Tagging" `
            -Status "FAIL" `
            -Severity "Low" `
            -Resource "All Resources" `
            -Description "Poor tag coverage: $tagCoverage% — $($untagged.Count) resources untagged" `
            -Remediation "Implement Azure Policy to enforce tagging on all resources."
    }
} catch {
    Write-Host "  ⚠️  Could not check tags" `
        -ForegroundColor Yellow
}

# Check 6.3: Azure Policy assignments
try {
    $policyAssignments = Get-AzPolicyAssignment

    if ($policyAssignments.Count -ge 5) {
        Add-Finding `
            -Category "Governance" `
            -Control "Azure Policy" `
            -Status "PASS" `
            -Severity "Medium" `
            -Resource "Azure Policy" `
            -Description "$($policyAssignments.Count) policies assigned" `
            -Remediation "No action required"
    } elseif ($policyAssignments.Count -gt 0) {
        Add-Finding `
            -Category "Governance" `
            -Control "Azure Policy" `
            -Status "WARN" `
            -Severity "Medium" `
            -Resource "Azure Policy" `
            -Description "Only $($policyAssignments.Count) policies assigned" `
            -Remediation "Add security policies: CIS benchmark, Azure Security Benchmark, and custom policies."
    } else {
        Add-Finding `
            -Category "Governance" `
            -Control "Azure Policy" `
            -Status "FAIL" `
            -Severity "Medium" `
            -Resource "Azure Policy" `
            -Description "No Azure policies assigned" `
            -Remediation "Assign Azure Security Benchmark and CIS policies to enforce compliance."
    }
} catch {
    Write-Host "  ⚠️  Could not check policies" `
        -ForegroundColor Yellow
}

# Check 6.4: Management Groups
try {
    $mgGroups = Get-AzManagementGroup `
        -ErrorAction SilentlyContinue

    if ($mgGroups.Count -gt 1) {
        Add-Finding `
            -Category "Governance" `
            -Control "Management Groups" `
            -Status "PASS" `
            -Severity "Low" `
            -Resource "Management Groups" `
            -Description "$($mgGroups.Count) management groups configured" `
            -Remediation "No action required"
    } else {
        Add-Finding `
            -Category "Governance" `
            -Control "Management Groups" `
            -Status "WARN" `
            -Severity "Low" `
            -Resource "Management Groups" `
            -Description "Management groups not fully configured" `
            -Remediation "Implement management group hierarchy for enterprise governance at scale."
    }
} catch {
    Write-Host "  ⚠️  Could not check management groups" `
        -ForegroundColor Yellow
}

# ============================================
# CALCULATE FINAL SCORES
# ============================================

$totalChecks    = $findings.Count
$overallScore   = [math]::Round(
    ($passedCount / $totalChecks) * 100, 0
)

$criticalFails = ($findings |
    Where-Object {
        $_.Status -eq "FAIL" -and
        $_.Severity -eq "Critical"
    }).Count

$highFails = ($findings |
    Where-Object {
        $_.Status -eq "FAIL" -and
        $_.Severity -eq "High"
    }).Count

$scoreGrade = switch ($overallScore) {
    {$_ -ge 90} {"A — Excellent"}
    {$_ -ge 80} {"B — Good"}
    {$_ -ge 70} {"C — Acceptable"}
    {$_ -ge 60} {"D — Needs Work"}
    default     {"F — Critical Issues"}
}

Write-Host "`n=== ASSESSMENT COMPLETE ===" `
    -ForegroundColor Cyan
Write-Host "Total Checks:   $totalChecks" -ForegroundColor White
Write-Host "Passed:         $passedCount" -ForegroundColor Green
Write-Host "Failed:         $failedCount" -ForegroundColor Red
Write-Host "Warnings:       $warningCount" -ForegroundColor Yellow
Write-Host "Overall Score:  $overallScore% ($scoreGrade)" `
    -ForegroundColor Cyan

# ============================================
# GENERATE HTML REPORT
# ============================================

Write-Host "`nGenerating HTML report..." -ForegroundColor Cyan

# Build findings table rows
$findingsRows = ""
foreach ($finding in $findings) {
    $statusIcon = switch ($finding.Status) {
        "PASS" {"✅"}
        "FAIL" {"❌"}
        "WARN" {"⚠️"}
    }

    $statusClass = switch ($finding.Status) {
        "PASS" {"status-pass"}
        "FAIL" {"status-fail"}
        "WARN" {"status-warn"}
    }

    $severityClass = switch ($finding.Severity) {
        "Critical" {"sev-critical"}
        "High"     {"sev-high"}
        "Medium"   {"sev-medium"}
        "Low"      {"sev-low"}
    }

    $findingsRows += @"
        <tr class='$statusClass-row'>
            <td>$($finding.Category)</td>
            <td>$($finding.Control)</td>
            <td><span class='$statusClass'>
                $statusIcon $($finding.Status)
            </span></td>
            <td><span class='$severityClass'>
                $($finding.Severity)
            </span></td>
            <td>$($finding.Resource)</td>
            <td>$($finding.Description)</td>
            <td class='remediation'>$($finding.Remediation)</td>
        </tr>
"@
}

# Score color
$scoreColor = switch ($overallScore) {
    {$_ -ge 80} {"#3fb950"}
    {$_ -ge 60} {"#e3b341"}
    default     {"#ff7b72"}
}

$html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Azure Security Assessment — Uzma Sami</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', Arial, sans-serif;
               background: #0d1117; color: #e6edf3;
               padding: 30px; }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { background: linear-gradient(
                      135deg, #1f6feb, #388bfd);
                  padding: 30px; border-radius: 16px;
                  margin-bottom: 25px; }
        .header h1 { font-size: 28px; margin-bottom: 8px; }
        .header p { opacity: 0.85; font-size: 14px;
                    margin-top: 4px; }
        .score-section { display: grid;
                         grid-template-columns: 200px 1fr;
                         gap: 20px; margin-bottom: 25px; }
        .score-circle { background: #161b22;
                        border: 3px solid $scoreColor;
                        border-radius: 50%; width: 180px;
                        height: 180px; display: flex;
                        flex-direction: column;
                        align-items: center;
                        justify-content: center;
                        text-align: center; }
        .score-number { font-size: 56px; font-weight: 700;
                        color: $scoreColor; }
        .score-label { font-size: 13px; color: #8b949e;
                       margin-top: 4px; }
        .score-grade { font-size: 16px; font-weight: 600;
                       color: $scoreColor; margin-top: 8px; }
        .metric-grid { display: grid;
                       grid-template-columns: repeat(4,1fr);
                       gap: 15px; }
        .metric-box { background: #161b22;
                      border: 1px solid #30363d;
                      border-radius: 10px; padding: 20px;
                      text-align: center; }
        .metric-number { font-size: 36px; font-weight: 700; }
        .metric-pass { color: #3fb950; }
        .metric-fail { color: #ff7b72; }
        .metric-warn { color: #e3b341; }
        .metric-total { color: #388bfd; }
        .metric-label { font-size: 13px; color: #8b949e;
                        margin-top: 6px; }
        h2 { color: #388bfd; border-left: 4px solid #1f6feb;
             padding-left: 12px; margin: 25px 0 15px;
             font-size: 18px; }
        .controls-grid { display: grid;
                         grid-template-columns: repeat(3,1fr);
                         gap: 15px; margin-bottom: 25px; }
        .control-card { background: #161b22;
                        border: 1px solid #30363d;
                        border-radius: 10px; padding: 15px; }
        .control-card h3 { font-size: 14px; color: #388bfd;
                           margin-bottom: 10px; }
        .control-item { display: flex; justify-content: space-between;
                        align-items: center; padding: 5px 0;
                        border-bottom: 1px solid #21262d;
                        font-size: 12px; }
        table { width: 100%; border-collapse: collapse;
                background: #161b22; border-radius: 10px;
                overflow: hidden; }
        th { background: #1f6feb; color: white; padding: 12px;
             text-align: left; font-size: 12px; }
        td { padding: 10px 12px; border-bottom: 1px solid #21262d;
             font-size: 12px; vertical-align: top; }
        .status-pass { background: #1a4731; color: #3fb950;
                       padding: 3px 8px; border-radius: 12px;
                       font-size: 11px; white-space: nowrap; }
        .status-fail { background: #4d1919; color: #ff7b72;
                       padding: 3px 8px; border-radius: 12px;
                       font-size: 11px; white-space: nowrap; }
        .status-warn { background: #3d2b00; color: #e3b341;
                       padding: 3px 8px; border-radius: 12px;
                       font-size: 11px; white-space: nowrap; }
        .sev-critical { background: #6e1010; color: #ff9999;
                        padding: 2px 6px; border-radius: 10px;
                        font-size: 11px; }
        .sev-high { background: #4d2800; color: #ffa657;
                    padding: 2px 6px; border-radius: 10px;
                    font-size: 11px; }
        .sev-medium { background: #3d2b00; color: #e3b341;
                      padding: 2px 6px; border-radius: 10px;
                      font-size: 11px; }
        .sev-low { background: #1a3028; color: #56d364;
                   padding: 2px 6px; border-radius: 10px;
                   font-size: 11px; }
        .status-fail-row { background: #1a0a0a; }
        .status-warn-row { background: #1a1500; }
        .remediation { color: #8b949e; font-style: italic; }
        .filter-bar { background: #161b22; padding: 15px;
                      border-radius: 10px; margin-bottom: 15px;
                      display: flex; gap: 10px; flex-wrap: wrap; }
        .filter-btn { background: #21262d; border: 1px solid #30363d;
                      color: #e6edf3; padding: 6px 14px;
                      border-radius: 20px; cursor: pointer;
                      font-size: 12px; transition: all 0.2s; }
        .filter-btn:hover { background: #1f6feb; }
        .filter-btn.active { background: #1f6feb; }
        footer { margin-top: 40px; padding-top: 20px;
                 border-top: 1px solid #21262d;
                 color: #8b949e; font-size: 12px;
                 text-align: center; }
    </style>
    <script>
        function filterFindings(status) {
            const rows = document.querySelectorAll(
                'tbody tr'
            );
            rows.forEach(row => {
                if (status === 'ALL') {
                    row.style.display = '';
                } else {
                    const statusCell = row.querySelector(
                        'td:nth-child(3)'
                    );
                    if (statusCell &&
                        statusCell.textContent.includes(status)) {
                        row.style.display = '';
                    } else {
                        row.style.display = 'none';
                    }
                }
            });

            document.querySelectorAll('.filter-btn')
                .forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
        }
    </script>
</head>
<body>
<div class='container'>

    <div class='header'>
        <h1>🔐 Azure Security Assessment Report</h1>
        <p>Engineer: Uzma Sami | AZ-104 | AZ-500</p>
        <p>Subscription: $subName</p>
        <p>Assessment Date: $reportDate</p>
        <p>Tool Version: 1.0 — azSecurityAssessor</p>
    </div>

    <div class='score-section'>
        <div class='score-circle'>
            <div class='score-number'>$overallScore%</div>
            <div class='score-label'>Security Score</div>
            <div class='score-grade'>$scoreGrade</div>
        </div>
        <div class='metric-grid'>
            <div class='metric-box'>
                <div class='metric-number metric-total'>
                    $totalChecks
                </div>
                <div class='metric-label'>Total Controls</div>
            </div>
            <div class='metric-box'>
                <div class='metric-number metric-pass'>
                    $passedCount
                </div>
                <div class='metric-label'>Passed ✅</div>
            </div>
            <div class='metric-box'>
                <div class='metric-number metric-fail'>
                    $failedCount
                </div>
                <div class='metric-label'>Failed ❌</div>
            </div>
            <div class='metric-box'>
                <div class='metric-number metric-warn'>
                    $warningCount
                </div>
                <div class='metric-label'>Warnings ⚠️</div>
            </div>
        </div>
    </div>

    <h2>📋 Categories Assessed</h2>
    <div class='controls-grid'>
        <div class='control-card'>
            <h3>🔑 Identity & Access (4 controls)</h3>
            <div class='control-item'>
                <span>Global Admin Count</span>
            </div>
            <div class='control-item'>
                <span>Guest User Accounts</span>
            </div>
            <div class='control-item'>
                <span>Conditional Access</span>
            </div>
            <div class='control-item'>
                <span>Service Principal Secrets</span>
            </div>
        </div>
        <div class='control-card'>
            <h3>🌐 Network Security (4 controls)</h3>
            <div class='control-item'>
                <span>NSG Coverage</span>
            </div>
            <div class='control-item'>
                <span>RDP/SSH Internet Access</span>
            </div>
            <div class='control-item'>
                <span>Unused Public IPs</span>
            </div>
            <div class='control-item'>
                <span>DDoS Protection</span>
            </div>
        </div>
        <div class='control-card'>
            <h3>💾 Data Security (5 controls)</h3>
            <div class='control-item'>
                <span>Storage HTTPS</span>
            </div>
            <div class='control-item'>
                <span>Storage Public Access</span>
            </div>
            <div class='control-item'>
                <span>Storage TLS Version</span>
            </div>
            <div class='control-item'>
                <span>Key Vault Soft Delete</span>
            </div>
            <div class='control-item'>
                <span>SQL Server TLS</span>
            </div>
        </div>
        <div class='control-card'>
            <h3>📊 Logging & Monitoring (4 controls)</h3>
            <div class='control-item'>
                <span>Log Analytics Workspace</span>
            </div>
            <div class='control-item'>
                <span>Microsoft Sentinel</span>
            </div>
            <div class='control-item'>
                <span>Network Watcher</span>
            </div>
            <div class='control-item'>
                <span>Diagnostic Settings</span>
            </div>
        </div>
        <div class='control-card'>
            <h3>🛡️ Defender for Cloud (3 controls)</h3>
            <div class='control-item'>
                <span>Defender Plans</span>
            </div>
            <div class='control-item'>
                <span>Security Contacts</span>
            </div>
            <div class='control-item'>
                <span>Secure Score</span>
            </div>
        </div>
        <div class='control-card'>
            <h3>⚖️ Governance (4 controls)</h3>
            <div class='control-item'>
                <span>Resource Locks</span>
            </div>
            <div class='control-item'>
                <span>Resource Tagging</span>
            </div>
            <div class='control-item'>
                <span>Azure Policy</span>
            </div>
            <div class='control-item'>
                <span>Management Groups</span>
            </div>
        </div>
    </div>

    <h2>🔍 Detailed Findings</h2>
    <div class='filter-bar'>
        <button class='filter-btn active'
            onclick='filterFindings("ALL")'>
            All ($totalChecks)
        </button>
        <button class='filter-btn'
            onclick='filterFindings("FAIL")'>
            ❌ Failed ($failedCount)
        </button>
        <button class='filter-btn'
            onclick='filterFindings("WARN")'>
            ⚠️ Warnings ($warningCount)
        </button>
        <button class='filter-btn'
            onclick='filterFindings("PASS")'>
            ✅ Passed ($passedCount)
        </button>
    </div>

    <table>
        <thead>
            <tr>
                <th>Category</th>
                <th>Control</th>
                <th>Status</th>
                <th>Severity</th>
                <th>Resource</th>
                <th>Finding</th>
                <th>Remediation</th>
            </tr>
        </thead>
        <tbody>
            $findingsRows
        </tbody>
    </table>

    <footer>
        Azure Security Assessment Tool v1.0 |
        Uzma Sami | AZ-104 | AZ-500 |
        $reportDate<br>
        $totalChecks controls assessed across
        6 security categories
    </footer>
</div>
</body>
</html>
"@

# Save report
$reportFullPath = Join-Path $OutputPath $reportFileName
$html | Out-File $reportFullPath -Encoding UTF8

Write-Host "✅ Report saved: $reportFullPath" `
    -ForegroundColor Green

# Export CSV summary
$findings | Export-Csv `
    -Path (Join-Path $OutputPath "findings-summary.csv") `
    -NoTypeInformation

Write-Host "✅ CSV summary exported!" -ForegroundColor Green

# Open report
if ($OpenReport) {
    #Start-Process $reportFullPath
    Write-Host "✅ Report opened in browser!" `
        -ForegroundColor Green
}

Write-Host @"

╔════════════════════════════════════════════╗
║         ASSESSMENT COMPLETE!               ║
║                                            ║
║  Score:    $overallScore%                          
║  Grade:    $scoreGrade
║  Passed:   $passedCount controls                    
║  Failed:   $failedCount controls                    
║  Warnings: $warningCount controls                   
║                                            ║
║  Report saved to: $OutputPath
╚════════════════════════════════════════════╝
"@ -ForegroundColor Cyan


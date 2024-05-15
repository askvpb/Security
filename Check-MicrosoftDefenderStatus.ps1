
# Script Name: Check-MicrosoftDefenderStatus.ps1
# Script to check the configuration status of Microsoft Defender for Endpoint

# Check if running as Administrator
if (-NOT (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion")) {
    Write-Warning "Please run this script as an Administrator!"
    exit
}

# ASR Rule Mapping
$asrRuleMapping = @{
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block abuse of exploited vulnerable signed drivers"
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Block Adobe Reader from creating child processes"
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Block all Office applications from creating child processes"
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "Block executable content from email client and webmail"
    "01443614-cd74-433a-b99e-2ecdc07bfc25" = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Block execution of potentially obfuscated scripts"
    "d3e037e1-3eb8-44c8-a917-57927947596d" = "Block JavaScript or VBScript from launching downloaded executable content"
    "3b576869-a4ec-4529-8536-b80a7769e899" = "Block Office applications from creating executable content"
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = "Block Office applications from injecting code into other processes"
    "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office communication application from creating child processes"
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block persistence through WMI event subscription"
    "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Block process creations originating from PSExec and WMI commands"
    "33ddedf1-c6e0-47cb-833e-de6133960387" = "Block rebooting machine in Safe Mode (preview)"
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted and unsigned processes that run from USB"
    "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" = "Block use of copied or impersonated system tools (preview)"
    "a8f5898e-1dc8-49a9-9878-85004b8a61e6" = "Block Webshell creation for Servers"
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "Block Win32 API calls from Office macros"
    "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Use advanced protection against ransomware"
}

# Function to check the status of Microsoft Defender Antivirus
function Check-DefenderAntivirus {
    Write-Host "Checking Microsoft Defender Antivirus status..."
    $defenderStatus = Get-MpComputerStatus
    $amServiceEnabled = $defenderStatus.AMServiceEnabled
    $realTimeProtectionEnabled = $defenderStatus.RealTimeProtectionEnabled
    $onAccessProtectionEnabled = $defenderStatus.OnAccessProtectionEnabled

    Write-Host "AM Service Enabled: $amServiceEnabled"
    Write-Host "Real-Time Protection Enabled: $realTimeProtectionEnabled"
    Write-Host "On-Access Protection Enabled: $onAccessProtectionEnabled"
}

# Function to check if Microsoft Defender ATP is connected to the cloud
function Check-DefenderATPConnection {
    Write-Host "Checking Microsoft Defender ATP cloud connection..."
    $cloudProtectionEnabled = (Get-MpComputerStatus).CloudProtectionEnabled

    if ($cloudProtectionEnabled) {
        Write-Host "Microsoft Defender ATP is connected to the cloud."
    } else {
        Write-Host "Microsoft Defender ATP is NOT connected to the cloud."
    }
}

# Function to check the status of ASR rules
function Check-ASRRules {
    Write-Host "Checking Attack Surface Reduction (ASR) rules status..."
    $asrRules = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids

    if ($asrRules) {
        $asrRules | ForEach-Object {
            $ruleName = $asrRuleMapping[$_]
            Write-Host "$_ : $ruleName : Enabled"
        }
    } else {
        Write-Host "No ASR rules are enabled."
    }
}

# Function to list antivirus exclusions
function List-AVExclusions {
    Write-Host "Listing antivirus exclusions..."
    $exclusions = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath

    if ($exclusions) {
        $exclusions | ForEach-Object { Write-Host "Exclusion Path: $_" }
    } else {
        Write-Host "No antivirus exclusions are set."
    }
}

# Main script execution
Write-Host "Getting Microsoft Defender status..."

# Execute functions
Check-DefenderAntivirus
Check-DefenderATPConnection
Check-ASRRules
List-AVExclusions

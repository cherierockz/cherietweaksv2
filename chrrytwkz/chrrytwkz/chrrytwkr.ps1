#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

# Configuration
$logPath = "$env:ProgramData\CherieTweaker.log"
$backupDir = "$env:ProgramData\CherieTweaker\Backups"
$animationDuration = 3

# Color Themes
$themes = @{
    'Blood Moon' = @{ Primary='Red'; Accent='DarkRed' }
    'Cyberpunk'  = @{ Primary='Magenta'; Accent='Yellow' }
    'Matrix'     = @{ Primary='Green'; Accent='DarkGreen' }
    'Midnight'   = @{ Primary='Cyan'; Accent='DarkBlue' }
}
$global:CurrentTheme = 'Blood Moon'
$Host.UI.RawUI.ForegroundColor = $themes[$CurrentTheme].Primary
$global:PerformanceMode = $false

# P/Invoke declaration for animation disable
$Signature = @"
[DllImport("user32.dll", EntryPoint = "SystemParametersInfo")]
public static extern bool SystemParametersInfo(uint uiAction, uint uiParam, uint pvParam, uint fWinIni);
"@
$SystemParametersInfo = Add-Type -MemberDefinition $Signature -Name "Win32SystemParametersInfo" -Namespace Win32Functions -PassThru

# Initialize logging
function Log($message, $type = "INFO") {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$type] $message"
    Add-Content -Path $logPath -Value $logEntry
}

try {
    # Ensure backup directory exists
    if (-not (Test-Path $backupDir)) { New-Item -ItemType Directory -Path $backupDir | Out-Null }
    
    # Clear existing log
    if (Test-Path $logPath) { Clear-Content $logPath }
    
    Log "CherieTweaker V2.1 started at $(Get-Date)"
    Log "System Information: $((Get-WmiObject Win32_OperatingSystem).Caption)"
}
catch { Write-Host "Initialization error: $_" -ForegroundColor Red }


function Show-Header {
    Clear-Host
    $color = $themes[$CurrentTheme].Primary
    Write-Host ""
    Write-Host "_________   ___ ________________________.___________________________      _____________   _____   ____  __.  _________ ____   ____________  " -ForegroundColor $color
    Write-Host "\_   ___ \ /   |   \_   _____/\______   \   \_   _____/\__    ___/  \    /  \_   _____/  /  _  \ |    |/ _| /   _____/ \   \ /   /\_____  \ " -ForegroundColor $color
    Write-Host "/    \  \//    ~    \    __)_  |       _/   ||    __)_   |    |  \   \/\/   /|    __)_  /  /_\  \|      <   \_____  \   \   Y   /  /  ____/ " -ForegroundColor $color
    Write-Host "\     \___\    Y    /        \ |    |   \   ||        \  |    |   \        / |        \/    |    \    |  \  /        \   \     /  /       \ " -ForegroundColor $color
    Write-Host " \______  /\___|_  /_______  / |____|_  /___/_______  /  |____|    \__/\  / /_______  /\____|__  /____|__ \/_______  /    \___/   \_______ \" -ForegroundColor $color
    Write-Host "        \/       \/        \/         \/            \/                  \/          \/         \/        \/        \/                     \/" -ForegroundColor $color
    Write-Host ""
    Write-Host "CHERIETWEAKER V2.1 - SYSTEM OPTIMIZATION SUITE" -ForegroundColor $color
    Write-Host "DEVELOPED BY CHERIEROCKZ | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor $color
    Write-Host "================================================================================" -ForegroundColor $color
    Write-Host ""
}

function Show-BinaryAnimation {
    $endTime = (Get-Date).AddSeconds($animationDuration)
    $colors = @('DarkGreen', 'Green', 'DarkCyan', 'Cyan')
    
    while ((Get-Date) -lt $endTime) {
        Clear-Host
        for ($i = 0; $i -lt 15; $i++) {
            $line = -join (1..80 | ForEach-Object { 
                if ((Get-Random) -gt 0.5) { '1' } else { '0' } 
            })
            $color = $colors | Get-Random
            Write-Host $line -ForegroundColor $color
        }
        Start-Sleep -Milliseconds 100
    }
    Clear-Host
}

function Show-AsciiLogo {
    $accent = $themes[$CurrentTheme].Primary
    $logo = @'
     _____           _______                   _____                    _____                    _____                    _____                    _____          
     /\    \         /::\    \                 /\    \                  /\    \                  /\    \                  /\    \                  /\    \         
    /::\____\       /::::\    \               /::\    \                /::\    \                /::\    \                /::\____\                /::\    \        
   /:::/    /      /::::::\    \             /::::\    \              /::::\    \               \:::\    \              /::::|   |               /::::\    \       
  /:::/    /      /::::::::\    \           /::::::\    \            /::::::\    \               \:::\    \            /:::::|   |              /::::::\    \      
 /:::/    /      /:::/  \:::\    \         /:::/\:::\    \          /:::/\:::\    \                \:::\    \          /::::::|   |             /:::/\:::\    \     
/:::/    /      /:::/    \:::\    \       /:::/__\:::\    \        /:::/  \:::\    \               \:::\    \        /:::/|::|   |            /:::/  \:::\    \    
/:::/    /      /:::/    / \:::\    \     /::::\   \:::\    \      /:::/    \:::\    \              /::::\    \      /:::/ |::|   |           /:::/    \:::\    \   
/:::/    /      /:::/____/   \:::\____\   /::::::\   \:::\    \    /:::/    / \:::\    \    ____    /::::::\    \    /:::/  |::|   | _____    /:::/    / \:::\    \  
/:::/    /      |:::|    |    |:::|    | /:::/\:::\   \:::\    \  /:::/    /   \:::\ ___\  /\   \  /:::/\:::\    \  /:::/   |::|   |/\    \  /:::/    /   \:::\ ___\ 
/:::/____/       |:::|____|    |:::|    |/:::/  \:::\   \:::\____\/:::/____/     \:::|    |/::\   \/:::/  \:::\____\/:: /    |::|   /::\____\/:::/____/  ___\:::|    |
\:::\    \        \:::\    \  /:::/    / \::/    \:::\  /:::/    /\:::\    \     /:::|____|\:::\  /:::/    \::/    /\::/    /|::|  /:::/    /\:::\    \ /\  /:::|____|
 \:::\    \        \:::\    \/:::/    /   \/____/ \:::\/:::/    /  \:::\    \   /:::/    /  \:::\/:::/    / \/____/  \/____/ |::| /:::/    /  \:::\    /::\ \::/    / 
  \:::\    \        \:::\    /:::/    /             \::::::/    /    \:::\    \ /:::/    /    \::::::/    /                   |::|/:::/    /    \:::\   \:::\ \/____/  
   \:::\    \        \:::\__/:::/    /               \::::/    /      \:::\    /:::/    /      \::::/____/                    |::::::/    /      \:::\   \:::\____\    
    \:::\    \        \::::::::/    /                /:::/    /        \:::\  /:::/    /        \:::\    \                    |:::::/    /        \:::\  /:::/    /    
     \:::\    \        \::::::/    /                /:::/    /          \:::/:::/    /          \:::\    \                   |::::/    /          \:::/:::/    /     
      \:::\    \        \::::/    /                /:::/    /            \::::::/    /            \:::\    \                  /:::/    /            \::::::/    /      
       \:::\____\        \::/____/                /:::/    /              \::::/    /              \:::\____\                /:::/    /              \::::/    /       
        \::/    /                                 \::/    /                \::/____/                \::/    /                \::/    /                \::/____/        
         \/____/                                   \/____/                                           \/____/                  \/____/                                   
'@
    $logo.Split("`n") | ForEach-Object { Write-Host $_ -ForegroundColor $accent }
    Start-Sleep -Seconds 2
}


function Backup-Registry([string]$path) {
    $regPath = $path -replace "^HKLM:\\", "HKEY_LOCAL_MACHINE\" `
                     -replace "^HKCU:\\", "HKEY_CURRENT_USER\"
    $backupFile = Join-Path $backupDir "registry_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
    reg export $regPath $backupFile /y 2>&1 | Out-Null
    Log "Backed up registry: $path -> $backupFile"
    return $backupFile
}

function Confirm-Action($action) {
    $choice = Read-Host "`n$action (Y/N)?"
    return $choice -in 'Y','y'
}

function Select-ColorTheme {
    Write-Host "AVAILABLE THEMES:" -ForegroundColor $themes[$CurrentTheme].Primary
    $i = 1
    foreach ($t in $themes.Keys) {
        Write-Host "$i. $t" -ForegroundColor $themes[$CurrentTheme].Primary
        $i++
    }
    $selection = Read-Host "Select theme number"
    $index = [int]$selection - 1
    if ($index -ge 0 -and $index -lt $themes.Keys.Count) {
        $global:CurrentTheme = $themes.Keys[$index]
        $Host.UI.RawUI.ForegroundColor = $themes[$CurrentTheme].Primary
    }
}

function Toggle-PerformanceMode {
    $global:PerformanceMode = -not $global:PerformanceMode
    if ($PerformanceMode) {
        powercfg /setactive SCHEME_MIN
        Write-Host "Performance Mode ON" -ForegroundColor $themes[$CurrentTheme].Primary
    } else {
        powercfg /setactive SCHEME_BALANCED
        Write-Host "Performance Mode OFF" -ForegroundColor $themes[$CurrentTheme].Primary
    }
    Log "Performance Mode: $PerformanceMode"
}

function Start-TurboMode {
    Get-AppxPackage | Where-Object {$_.IsFramework -ne $true} | ForEach-Object { Stop-Process -Id $_.PackageFullName -ErrorAction SilentlyContinue }
    $services = 'SysMain','WSearch'
    foreach ($s in $services) { Stop-Service $s -ErrorAction SilentlyContinue; Set-Service $s -StartupType Disabled }
    Log 'Turbo Mode executed'
}

function Enable-GameMode {
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AllowAutoGameMode' -Value 1 -Type DWord
    Log 'Game Mode enabled'
}

function Optimize-SSD {
    Stop-Service SysMain -ErrorAction SilentlyContinue
    Set-Service SysMain -StartupType Disabled
    defrag C: /L | Out-Null
    powercfg /h off
    Log 'SSD Optimized'
}

function Clean-RAM {
    $tool = Join-Path $PSScriptRoot 'EmptyStandbyList.exe'
    if (Test-Path $tool) { & $tool workingsets }
    [System.GC]::Collect()
    Log 'RAM cleaned'
}

function Invoke-SpyBlocker {
    Add-Content -Path "$env:windir\System32\drivers\etc\hosts" -Value "0.0.0.0 telemetry.microsoft.com"
    Stop-Service DiagTrack -ErrorAction SilentlyContinue
    Set-Service DiagTrack -StartupType Disabled
    Log 'SpyBlocker applied'
}


$tweaks = @(

    @{
        Name = "Change Color Theme"
        Category = "Settings"
        Action = { Select-ColorTheme }
    },

    @{
        Name = "Toggle Performance Mode"
        Category = "Performance Tweaks"
        Action = { Toggle-PerformanceMode }
    },
    @{
        Name = "Turbo Mode"
        Category = "Performance Tweaks"
        Action = { Start-TurboMode }
    },

    @{
        Name = "Game Mode"
        Category = "Performance Tweaks"
        Action = { Enable-GameMode }
    },

    @{
        Name = "SSD Optimizer"
        Category = "Maintenance"
        Action = { Optimize-SSD }
    },

    @{
        Name = "RAM Cleaner"
        Category = "System Tools"
        Action = { Clean-RAM }
    },

    @{
        Name = "SpyBlocker"
        Category = "Privacy & Security"
        Action = { Invoke-SpyBlocker }
    },
    
    @{
        Name = "Disable Telemetry Services"
        Category = "System Performance"
        Action = {
            $services = @("DiagTrack", "dmwappushservice", "DPS")
            foreach ($svc in $services) {
                try {
                    if ((Get-Service $svc -ErrorAction SilentlyContinue).Status -ne 'Stopped') {
                        Stop-Service $svc -Force
                        Set-Service $svc -StartupType Disabled
                        Log "Disabled service: $svc"
                    }
} catch {
    Log-Message "Error disabling $svc: $($_.Exception.Message)" "ERROR"
}

            
            $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            Set-ItemProperty -Path $regPath -Name "AllowTelemetry" -Value 0 -Type DWord
        }
    },
    
    @{
        Name = "Optimize Power Plan"
        Category = "System Performance"
        Action = {
            powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  
            powercfg /h off
            Log "Optimized power settings"
        }
    },
    

    @{
        Name = "Disable Activity History"
        Category = "Privacy & Security"
        Action = {
            $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            Set-ItemProperty -Path $regPath -Name "EnableActivityFeed" -Value 0 -Type DWord
            Set-ItemProperty -Path $regPath -Name "PublishUserActivities" -Value 0 -Type DWord
            Log "Disabled activity history"
        }
    },
    
    @{
        Name = "Disable Location Tracking"
        Category = "Privacy & Security"
        Action = {
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            Set-ItemProperty -Path $regPath -Name "Value" -Value "Deny" -Type String
            Log "Disabled location tracking"
        }
    },
    

    @{
        Name = "Remove OneDrive"
        Category = "App Management"
        Action = {
            try {
                $onedrive = Get-Process onedrive -ErrorAction SilentlyContinue
                if ($onedrive) { $onedrive | Stop-Process -Force }
                
                $path = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
                if (Test-Path $path) {
                    Start-Process $path -ArgumentList "/uninstall" -NoNewWindow -Wait
                }
                
                Get-AppxPackage "*OneDrive*" | Remove-AppxPackage
                Log "Removed OneDrive"
            } catch { Log "Error removing OneDrive: $_" "ERROR" }
        }
    },
    
    @{
        Name = "Remove Bloatware Apps"
        Category = "App Management"
        Action = {
            $apps = @(
                "Microsoft.BingNews", "Microsoft.GetHelp", "Microsoft.Getstarted",
                "Microsoft.MicrosoftOfficeHub", "Microsoft.MicrosoftSolitaireCollection",
                "Microsoft.People", "Microsoft.SkypeApp", "Microsoft.WindowsAlarms",
                "Microsoft.WindowsCamera", "Microsoft.WindowsMaps", "Microsoft.WindowsSoundRecorder",
                "Microsoft.XboxApp", "Microsoft.XboxGameOverlay", "Microsoft.XboxIdentityProvider",
                "Microsoft.YourPhone", "Microsoft.ZuneMusic", "Microsoft.ZuneVideo"
            )
            
            foreach ($app in $apps) {
                try {
                    Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage
                    Get-AppxProvisionedPackage -Online | 
                        Where-Object DisplayName -Like $app | 
                        Remove-AppxProvisionedPackage -Online
                    Log "Removed: $app"
                } catch { Log "Error removing $app: $_" "ERROR" }
            }
        }
    },
    

    @{
        Name = "Clean Temporary Files"
        Category = "Disk Cleanup"
        Action = {
            try {
                Get-ChildItem $env:TEMP, ${env:windir}\Temp -Recurse -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                CleanMgr /sagerun:1 | Out-Null
                Log "Cleaned temporary files"
            } catch { Log "Error cleaning temp files: $_" "ERROR" }
        }
    },
    
    @{
        Name = "Clear System Cache"
        Category = "Disk Cleanup"
        Action = {
            try {
                ipconfig /flushdns | Out-Null
                DISM /Online /Cleanup-Image /StartComponentCleanup | Out-Null
                Log "Cleared system cache"
            } catch { Log "Error clearing cache: $_" "ERROR" }
        }
    },
    
   
    @{
        Name = "Optimize Network Settings"
        Category = "Network"
        Action = {
            try {
                Set-NetTCPSetting -InternetCustom -CongestionProvider Cubic
                Set-DnsClientGlobalSetting -SuffixSearchList @("")
                Log "Optimized network settings"
            } catch { Log "Error optimizing network: $_" "ERROR" }
        }
    },
    

    @{
        Name = "Disable Animations"
        Category = "UI Tweaks"
        Action = {
            try {
                $regPath = "HKCU:\Control Panel\Desktop\WindowMetrics"
                Set-ItemProperty -Path $regPath -Name "MinAnimate" -Value 0
                
                $SystemParametersInfo::SystemParametersInfo(0x0049, 0, 0, 2) | Out-Null  # SPI_SETANIMATION
                Log "Disabled animations"
            } catch { Log "Error disabling animations: $_" "ERROR" }
        }
    }
)


function Show-MainMenu {
    Show-Header
    Write-Host "CATEGORIES:" -ForegroundColor Cyan
    $categories = $tweaks.Category | Select-Object -Unique
    for ($i = 0; $i -lt $categories.Count; $i++) {
        Write-Host "$($i+1). $($categories[$i])"
    }
    
    Write-Host "`nACTIONS:" -ForegroundColor Cyan
    Write-Host "C. Run All Tweaks"
    Write-Host "R. Restore System"
    Write-Host "L. View Logs"
    Write-Host "X. Exit"
    
    $choice = Read-Host "`nSelect an option"
    return $choice
}


function Invoke-Tweak($tweak) {
    Show-Header
    Write-Host "Executing: $($tweak.Name)" -ForegroundColor Yellow
    Write-Host "Category: $($tweak.Category)" -ForegroundColor Yellow
    Write-Host "-" * 80
    
    try {
        & $tweak.Action
        Write-Host "`nSUCCESS: Operation completed" -ForegroundColor Green
        Log "Executed: $($tweak.Name)" "SUCCESS"
    } catch {
        Write-Host "`nERROR: $($_.Exception.Message)" -ForegroundColor Red
        Log "Failed: $($tweak.Name) - $($_.Exception.Message)" "ERROR"
    }
    
    Read-Host "`nPress Enter to continue..."
}


function Restore-System {
    Show-Header
    Write-Host "SYSTEM RESTORE OPTIONS" -ForegroundColor Cyan
    Write-Host "1. Restore from registry backups"
    Write-Host "2. Reset Windows Update components"
    Write-Host "3. Restore default services"
    Write-Host "4. Back to main menu"
    
    switch (Read-Host "`nSelect restore option") {
        "1" {
            if (Test-Path $backupDir) {
                Get-ChildItem $backupDir -Filter *.reg | ForEach-Object {
                    Write-Host "Restoring $_..."
                    reg import $_.FullName 2>&1 | Out-Null
                }
                Write-Host "Registry restored" -ForegroundColor Green
            } else {
                Write-Host "No backups found" -ForegroundColor Yellow
            }
        }
        "2" {
            try {
                Stop-Service wuauserv -Force
                Remove-Item "$env:SYSTEMROOT\SoftwareDistribution\*" -Recurse -Force
                Start-Service wuauserv
                Write-Host "Windows Update reset" -ForegroundColor Green
            } catch { Write-Host "Error resetting update: $_" -ForegroundColor Red }
        }
        "3" {
            try {
                Get-Service | Where-Object StartType -eq "Disabled" | Set-Service -StartupType Automatic
                Write-Host "Services restored to default" -ForegroundColor Green
            } catch { Write-Host "Error restoring services: $_" -ForegroundColor Red }
        }
    }
    if ($_ -ne "4") { Read-Host "`nPress Enter to continue..." }
}


try {
    Show-BinaryAnimation
    Show-AsciiLogo
    while ($true) {
        $choice = Show-MainMenu
        
        switch -Regex ($choice) {
            "^\d+$" {
                $index = [int]$choice - 1
                $category = ($tweaks.Category | Select-Object -Unique)[$index]
                $categoryTweaks = $tweaks | Where-Object { $_.Category -eq $category }
                
                Show-Header
                Write-Host "$category TWEAKS:" -ForegroundColor Cyan
                for ($i = 0; $i -lt $categoryTweaks.Count; $i++) {
                    Write-Host "$($i+1). $($categoryTweaks[$i].Name)"
                }
                Write-Host "0. Back"
                
                $tweakChoice = Read-Host "`nSelect tweak"
                if ($tweakChoice -ne "0") {
                    $tweakIndex = [int]$tweakChoice - 1
                    if ($tweakIndex -ge 0 -and $tweakIndex -lt $categoryTweaks.Count) {
                        if (Confirm-Action "Run $($categoryTweaks[$tweakIndex].Name)") {
                            Invoke-Tweak $categoryTweaks[$tweakIndex]
                        }
                    }
                }
            }
            "C" {
                if (Confirm-Action "Run ALL tweaks") {
                    foreach ($tweak in $tweaks) {
                        Invoke-Tweak $tweak
                    }
                }
            }
            "R" { Restore-System }
            "L" { Start-Process notepad.exe $logPath }
            "X" { exit }
        }
    }
} catch {
    Write-Host "Critical error: $_" -ForegroundColor Red
    Log "CRITICAL: $_" "ERROR"
    Read-Host "Press Enter to exit"
    exit 1
}
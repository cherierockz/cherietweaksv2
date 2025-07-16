#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

# Configuration
$logPath = "$env:ProgramData\CherieTweaker.log"
$backupDir = "$env:ProgramData\CherieTweaker\Backups"
$animationDuration = 3

# Color Themes
$themes = @{
    'Blood Moon' = @{ Primary = 'Red'; Accent = 'DarkRed' }
    'Cyberpunk'  = @{ Primary = 'Magenta'; Accent = 'Yellow' }
    'Matrix'     = @{ Primary = 'Green'; Accent = 'DarkGreen' }
    'Midnight'   = @{ Primary = 'Cyan'; Accent = 'DarkBlue' }
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
function Write-Log {
    param(
        [string]$message,
        [string]$type = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$type] $message"
    Add-Content -Path $logPath -Value $logEntry -ErrorAction SilentlyContinue
}

try {
    # Ensure backup directory exists
    if (-not (Test-Path $backupDir)) { 
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null 
    }
    
    # Clear existing log
    if (Test-Path $logPath) { Clear-Content $logPath -ErrorAction SilentlyContinue }
    
    Write-Log "CherieTweaker V2.1 started at $(Get-Date)"
    Write-Log "System Information: $((Get-WmiObject Win32_OperatingSystem).Caption)"
}
catch { 
    Write-Host "Initialization error: $_" -ForegroundColor Red 
    exit 1
}

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
            $color = $colors[(Get-Random -Maximum $colors.Count)]
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

function Backup-Registry {
    param([string]$path)
    
    try {
        $regPath = $path -replace "^HKLM:\\", "HKEY_LOCAL_MACHINE\" `
            -replace "^HKCU:\\", "HKEY_CURRENT_USER\"
        $backupFile = Join-Path $backupDir "registry_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
        
        # Create backup directory if it doesn't exist
        if (-not (Test-Path $backupDir)) {
            New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        }
        
        # Export registry key
        $process = Start-Process -FilePath "reg.exe" -ArgumentList "export `"$regPath`" `"$backupFile`" /y" -Wait -NoNewWindow -PassThru
        if ($process.ExitCode -ne 0) {
            throw "Registry export failed with exit code $($process.ExitCode)"
        }
        
        Write-Log "Backed up registry: $path -> $backupFile"
        return $backupFile
    }
    catch {
        Write-Log "Failed to backup registry $path : $_" -type "ERROR"
        return $null
    }
}

function Confirm-Action {
    param($action)
    
    do {
        $choice = Read-Host "`n$action (Y/N)?"
        if ($choice -notmatch '^[YNyn]$') {
            Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Yellow
        }
    } while ($choice -notmatch '^[YNyn]$')
    
    return $choice -in 'Y', 'y'
}

function Select-ColorTheme {
    Show-Header
    Write-Host "AVAILABLE THEMES:" -ForegroundColor $themes[$CurrentTheme].Primary
    $i = 1
    foreach ($t in $themes.Keys) {
        Write-Host "$i. $t" -ForegroundColor $themes[$CurrentTheme].Primary
        $i++
    }
    
    do {
        $selection = Read-Host "Select theme number (1-$($themes.Count))"
        $index = [int]$selection - 1
        if ($index -lt 0 -or $index -ge $themes.Keys.Count) {
            Write-Host "Invalid selection. Please try again." -ForegroundColor Red
        }
    } while ($index -lt 0 -or $index -ge $themes.Keys.Count)
    
    $global:CurrentTheme = $themes.Keys[$index]
    $Host.UI.RawUI.ForegroundColor = $themes[$CurrentTheme].Primary
    Write-Log "Changed theme to $CurrentTheme"
}

function Set-PerformanceModeToggle {
    $global:PerformanceMode = -not $global:PerformanceMode
    try {
        if ($PerformanceMode) {
            powercfg /setactive SCHEME_MIN | Out-Null
            Write-Host "Performance Mode ON" -ForegroundColor $themes[$CurrentTheme].Primary
        }
        else {
            powercfg /setactive SCHEME_BALANCED | Out-Null
            Write-Host "Performance Mode OFF" -ForegroundColor $themes[$CurrentTheme].Primary
        }
        Write-Log "Performance Mode: $PerformanceMode"
    }
    catch {
        Write-Host "Error toggling performance mode: $_" -ForegroundColor Red
        Write-Log "Error toggling performance mode: $_" -type "ERROR"
    }
}

function Start-TurboMode {
    try {
        # Stop unnecessary processes
        Get-Process | Where-Object {
            $_.ProcessName -in @('OneDrive', 'Teams', 'Skype', 'Spotify') -and
            $_.MainWindowHandle -ne 0
        } | Stop-Process -Force -ErrorAction SilentlyContinue
        
        # Disable unnecessary services
        $services = @('SysMain', 'WSearch', 'DiagTrack', 'dmwappushservice')
        foreach ($s in $services) {
            try {
                Stop-Service $s -Force -ErrorAction SilentlyContinue
                Set-Service $s -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Log "Disabled service: $s"
            }
            catch {
                Write-Log "Error disabling service $s : $_" -type "ERROR"
            }
        }
        
        # Clear memory
        Clear-RAM
        
        Write-Log 'Turbo Mode executed'
        Write-Host "Turbo Mode activated!" -ForegroundColor Green
    }
    catch {
        Write-Host "Error executing Turbo Mode: $_" -ForegroundColor Red
        Write-Log "Error executing Turbo Mode: $_" -type "ERROR"
    }
}

function Enable-GameMode {
    try {
        # Enable Game Mode in registry
        Set-ItemProperty -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AllowAutoGameMode' -Value 1 -Type DWord -ErrorAction Stop
        
        # Optimize game DVR settings
        $gameDvrPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\GraphicsDrivers"
        if (-not (Test-Path $gameDvrPath)) {
            New-Item -Path $gameDvrPath -Force | Out-Null
        }
        Set-ItemProperty -Path $gameDvrPath -Name "GameDVR_Enabled" -Value 1 -Type DWord
        Set-ItemProperty -Path $gameDvrPath -Name "GameDVR_FSEBehavior" -Value 2 -Type DWord
        
        Write-Log 'Game Mode enabled'
        Write-Host "Game Mode enabled successfully!" -ForegroundColor Green
    }
    catch {
        Write-Host "Error enabling Game Mode: $_" -ForegroundColor Red
        Write-Log "Error enabling Game Mode: $_" -type "ERROR"
    }
}

function Optimize-SSD {
    try {
        # Disable Superfetch/SysMain
        try {
            Stop-Service SysMain -Force -ErrorAction Stop
            Set-Service SysMain -StartupType Disabled -ErrorAction Stop
            Write-Log "Disabled SysMain service"
        }
        catch {
            Write-Log "Could not disable SysMain: $_" -type "WARNING"
        }
        
        # Disable hibernation
        powercfg /h off | Out-Null
        
        # Disable defragmentation for SSD
        Disable-MMAgent -MemoryCompression -ErrorAction SilentlyContinue
        
        # Optimize NTFS settings
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "NtfsDisableLastAccessUpdate" -Value 1 -Type DWord
        
        # Run TRIM
        Optimize-Volume -DriveLetter C -ReTrim -Verbose -ErrorAction SilentlyContinue
        
        Write-Log 'SSD Optimized'
        Write-Host "SSD optimization completed!" -ForegroundColor Green
    }
    catch {
        Write-Host "Error optimizing SSD: $_" -ForegroundColor Red
        Write-Log "Error optimizing SSD: $_" -type "ERROR"
    }
}

function Clear-RAM {
    try {
        # Try using EmptyStandbyList if available
        $tool = Join-Path $PSScriptRoot 'EmptyStandbyList.exe'
        if (Test-Path $tool) { 
            & $tool workingsets | Out-Null
        }
        else {
            # Alternative method if tool not available
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
        }
        
        Write-Log 'RAM cleaned'
        Write-Host "RAM cleaned successfully!" -ForegroundColor Green
    }
    catch {
        Write-Host "Error cleaning RAM: $_" -ForegroundColor Red
        Write-Log "Error cleaning RAM: $_" -type "ERROR"
    }
}

function Invoke-SpyBlocker {
    try {
        # Block telemetry domains in hosts file
        $hostsPath = "$env:windir\System32\drivers\etc\hosts"
        $telemetryDomains = @(
            "0.0.0.0 telemetry.microsoft.com",
            "0.0.0.0 vortex.data.microsoft.com",
            "0.0.0.0 settings-win.data.microsoft.com",
            "0.0.0.0 watson.telemetry.microsoft.com"
        )
        
        # Make backup of hosts file
        $hostsBackup = Join-Path $backupDir "hosts_$(Get-Date -Format 'yyyyMMdd_HHmmss').bak"
        Copy-Item $hostsPath $hostsBackup -Force
        
        # Add telemetry blocks
        foreach ($domain in $telemetryDomains) {
            if (-not (Select-String -Path $hostsPath -Pattern $domain.Split()[1])) {
                Add-Content -Path $hostsPath -Value $domain -ErrorAction Stop
            }
        }
        
        # Disable telemetry services
        $services = @("DiagTrack", "dmwappushservice", "DPS")
        foreach ($svc in $services) {
            try {
                Stop-Service $svc -Force -ErrorAction SilentlyContinue
                Set-Service $svc -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Log "Disabled telemetry service: $svc"
            }
            catch {
                Write-Log "Could not disable service $svc : $_" -type "WARNING"
            }
        }
        
        # Disable telemetry in registry
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name "AllowTelemetry" -Value 0 -Type DWord
        
        Write-Log 'SpyBlocker applied'
        Write-Host "Privacy protections applied successfully!" -ForegroundColor Green
    }
    catch {
        Write-Host "Error applying SpyBlocker: $_" -ForegroundColor Red
        Write-Log "Error applying SpyBlocker: $_" -type "ERROR"
    }
}

$tweaks = @(
    @{
        Name     = "Change Color Theme"
        Category = "Settings"
        Action   = { Select-ColorTheme }
    },
    @{
        Name     = "Toggle Performance Mode"
        Category = "Performance Tweaks"
        Action   = { Set-PerformanceModeToggle }
    },
    @{
        Name     = "Turbo Mode"
        Category = "Performance Tweaks"
        Action   = { Start-TurboMode }
    },
    @{
        Name     = "Game Mode"
        Category = "Performance Tweaks"
        Action   = { Enable-GameMode }
    },
    @{
        Name     = "SSD Optimizer"
        Category = "Maintenance"
        Action   = { Optimize-SSD }
    },
    @{
        Name     = "RAM Cleaner"
        Category = "System Tools"
        Action   = { Clear-RAM }
    },
    @{
        Name     = "SpyBlocker"
        Category = "Privacy & Security"
        Action   = { Invoke-SpyBlocker }
    },
    @{
        Name     = "Disable Telemetry Services"
        Category = "System Performance"
        Action   = {
            $services = @("DiagTrack", "dmwappushservice", "DPS")
            foreach ($svc in $services) {
                try {
                    $service = Get-Service $svc -ErrorAction SilentlyContinue
                    if ($service -and $service.Status -ne 'Stopped') {
                        Stop-Service $svc -Force
                        Set-Service $svc -StartupType Disabled
                        Write-Log "Disabled service: $svc"
                    } else {
                        Write-Log "Service $svc already stopped"
                    }
                } catch {
                    Write-Log "Error disabling $($svc): $($_.Exception.Message)" -type "ERROR"
                }
            }
        }
    },
    @{
        Name     = "Disable Windows Telemetry"
        Category = "Privacy"
        Action   = {
            try {
                $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
                if (-not (Test-Path $regPath)) { 
                    New-Item -Path $regPath -Force | Out-Null 
                }
                Set-ItemProperty -Path $regPath -Name "AllowTelemetry" -Value 0 -Type DWord -ErrorAction Stop
                Write-Log "Disabled Windows telemetry"
            }
            catch {
                Write-Log "Error disabling telemetry: $_" -type "ERROR"
            }
        }
    },
    @{
        Name     = "Optimize Power Plan"
        Category = "System Performance"
        Action   = {
            try {
                powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c | Out-Null
                powercfg /h off | Out-Null
                Write-Log "Optimized power settings"
                Write-Host "Power plan optimized for performance" -ForegroundColor Green
            }
            catch {
                Write-Log "Error optimizing power plan: $_" -type "ERROR"
                Write-Host "Error optimizing power plan: $_" -ForegroundColor Red
            }
        }
    },
    @{
        Name     = "Disable Activity History"
        Category = "Privacy & Security"
        Action   = {
            try {
                $regPath = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\System"
                if (-not (Test-Path $regPath)) { 
                    New-Item -Path $regPath -Force | Out-Null 
                }
                Set-ItemProperty -Path $regPath -Name "EnableActivityFeed" -Value 0 -Type DWord -ErrorAction Stop
                Set-ItemProperty -Path $regPath -Name "PublishUserActivities" -Value 0 -Type DWord -ErrorAction Stop
                Write-Log "Disabled activity history"
                Write-Host "Activity history tracking disabled" -ForegroundColor Green
            }
            catch {
                Write-Log "Error disabling activity history: $_" -type "ERROR"
                Write-Host "Error disabling activity history: $_" -ForegroundColor Red
            }
        }
    },
    @{
        Name     = "Disable Location Tracking"
        Category = "Privacy & Security"
        Action   = {
            try {
                $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
                if (-not (Test-Path $regPath)) { 
                    New-Item -Path $regPath -Force | Out-Null 
                }
                Set-ItemProperty -Path $regPath -Name "Value" -Value "Deny" -Type String -ErrorAction Stop
                Write-Log "Disabled location tracking"
                Write-Host "Location tracking disabled" -ForegroundColor Green
            }
            catch {
                Write-Log "Error disabling location tracking: $_" -type "ERROR"
                Write-Host "Error disabling location tracking: $_" -ForegroundColor Red
            }
        }
    },
    @{
        Name     = "Remove OneDrive"
        Category = "App Management"
        Action   = {
            try {
                # Kill OneDrive process
                $onedrive = Get-Process onedrive -ErrorAction SilentlyContinue
                if ($onedrive) { 
                    $onedrive | Stop-Process -Force 
                    Write-Log "Stopped OneDrive process"
                }
                
                # Run uninstaller
                $path = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
                if (Test-Path $path) {
                    Start-Process $path -ArgumentList "/uninstall" -NoNewWindow -Wait -ErrorAction Stop
                    Write-Log "Ran OneDrive uninstaller"
                }
                
                # Remove Appx packages
                Get-AppxPackage "*OneDrive*" | Remove-AppxPackage -ErrorAction SilentlyContinue
                Get-AppxProvisionedPackage -Online | Where-Object DisplayName -Like "*OneDrive*" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
                
                Write-Log "Removed OneDrive"
                Write-Host "OneDrive removed successfully" -ForegroundColor Green
            } 
            catch { 
                Write-Log "Error removing OneDrive: $_" -type "ERROR"
                Write-Host "Error removing OneDrive: $_" -ForegroundColor Red
            }
        }
    },
    @{
        Name     = "Remove Bloatware Apps"
        Category = "App Management"
        Action   = {
            try {
                $bloatApps = @(
                    "Microsoft.BingNews"
                    "Microsoft.BingWeather"
                    "Microsoft.GetHelp"
                    "Microsoft.Getstarted"
                    "Microsoft.Microsoft3DViewer"
                    "Microsoft.MicrosoftOfficeHub"
                    "Microsoft.MicrosoftSolitaireCollection"
                    "Microsoft.MSPaint"
                    "Microsoft.People"
                    "Microsoft.SkypeApp"
                    "Microsoft.WindowsAlarms"
                    "Microsoft.WindowsCamera"
                    "Microsoft.WindowsMaps"
                    "Microsoft.WindowsSoundRecorder"
                    "Microsoft.XboxApp"
                    "Microsoft.XboxGameOverlay"
                    "Microsoft.XboxIdentityProvider"
                    "Microsoft.YourPhone"
                    "Microsoft.ZuneMusic"
                    "Microsoft.ZuneVideo"
                )
                
                $removedCount = 0
                foreach ($app in $bloatApps) {
                    try {
                        $package = Get-AppxPackage -Name $app -AllUsers -ErrorAction SilentlyContinue
                        if ($package) {
                            $package | Remove-AppxPackage -ErrorAction SilentlyContinue
                            $removedCount++
                        }
                        
                        $provisioned = Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq $app -ErrorAction SilentlyContinue
                        if ($provisioned) {
                            $provisioned | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
                        }
                        
                        Write-Log "Removed $app"
                    }
                    catch {
                        Write-Log "Error removing $($app): $($_.Exception.Message)" -type "ERROR"
                    }
                }
                
                Write-Host "Removed $removedCount bloatware apps" -ForegroundColor Green
            }
            catch {
                Write-Log "Error removing bloatware: $_" -type "ERROR"
                Write-Host "Error removing bloatware: $_" -ForegroundColor Red
            }
        }
    },
    @{
        Name     = "Clean Temporary Files"
        Category = "Disk Cleanup"
        Action   = {
            try {
                # Clean temp directories
                Get-ChildItem $env:TEMP, "${env:windir}\Temp" -Recurse -Force -ErrorAction SilentlyContinue | 
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                
                # Run Disk Cleanup
                Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:1" -Wait -NoNewWindow -ErrorAction SilentlyContinue
                
                # Clear various caches
                Remove-Item "$env:LOCALAPPDATA\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
                Remove-Item "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\*" -Recurse -Force -ErrorAction SilentlyContinue
                
                Write-Log "Cleaned temporary files"
                Write-Host "Temporary files cleaned successfully" -ForegroundColor Green
            }
            catch {
                Write-Log "Error cleaning temp files: $_" -type "ERROR"
                Write-Host "Error cleaning temp files: $_" -ForegroundColor Red
            }
        }
    },
    @{
        Name     = "Clear System Cache"
        Category = "Disk Cleanup"
        Action   = {
            try {
                # Flush DNS
                ipconfig /flushdns | Out-Null
                
                # Clean DISM
                DISM /Online /Cleanup-Image /StartComponentCleanup | Out-Null
                
                # Clean WinSxS
                DISM /Online /Cleanup-Image /AnalyzeComponentStore | Out-Null
                
                Write-Log "Cleared system cache"
                Write-Host "System cache cleared successfully" -ForegroundColor Green
            }
            catch {
                Write-Log "Error clearing cache: $_" -type "ERROR"
                Write-Host "Error clearing cache: $_" -ForegroundColor Red
            }
        }
    },
    @{
        Name     = "Optimize Network Settings"
        Category = "Network"
        Action   = {
            try {
                # Set TCP settings
                $netAdapter = Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Select-Object -First 1
                if ($netAdapter) {
                    Set-NetTCPSetting -InterfaceAlias $netAdapter.InterfaceAlias -CongestionProvider Cubic
                }
                
                # Optimize DNS
                Set-DnsClientGlobalSetting -SuffixSearchList @("") -ErrorAction SilentlyContinue
                
                Write-Log "Optimized network settings"
                Write-Host "Network settings optimized" -ForegroundColor Green
            }
            catch {
                Write-Log "Error optimizing network: $_" -type "ERROR"
                Write-Host "Error optimizing network: $_" -ForegroundColor Red
            }
        }
    },
    @{
        Name     = "Disable Animations"
        Category = "UI Tweaks"
        Action   = {
            try {
                # Disable window animations
                $regPath = "HKCU:\Control Panel\Desktop"
                if (-not (Test-Path $regPath)) { 
                    New-Item -Path $regPath -Force | Out-Null 
                }
                Set-ItemProperty -Path $regPath -Name "UserPreferencesMask" -Value ([byte[]](0x90, 0x12, 0x03, 0x80, 0x10, 0x00, 0x00, 0x00)) -Type Binary
                
                # Disable system animations
                $SystemParametersInfo::SystemParametersInfo(0x0049, 0, 0, 2) | Out-Null  # SPI_SETANIMATION
                
                # Disable taskbar animations
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Value 0 -Type DWord
                
                Write-Log "Disabled animations"
                Write-Host "Animations disabled" -ForegroundColor Green
            }
            catch {
                Write-Log "Error disabling animations: $_" -type "ERROR"
                Write-Host "Error disabling animations: $_" -ForegroundColor Red
            }
        }
    }
)

function Show-MainMenu {
    Show-Header
    Write-Host "CATEGORIES:" -ForegroundColor $themes[$CurrentTheme].Primary
    $categories = $tweaks.Category | Select-Object -Unique
    for ($i = 0; $i -lt $categories.Count; $i++) {
        Write-Host "$($i+1). $($categories[$i])" -ForegroundColor $themes[$CurrentTheme].Primary
    }
    
    Write-Host "`nACTIONS:" -ForegroundColor $themes[$CurrentTheme].Primary
    Write-Host "C. Run All Tweaks" -ForegroundColor $themes[$CurrentTheme].Primary
    Write-Host "R. Restore System" -ForegroundColor $themes[$CurrentTheme].Primary
    Write-Host "L. View Logs" -ForegroundColor $themes[$CurrentTheme].Primary
    Write-Host "X. Exit" -ForegroundColor $themes[$CurrentTheme].Primary
    
    $choice = Read-Host "`nSelect an option"
    return $choice
}

function Invoke-Tweak {
    param($tweak)
    
    Show-Header
    Write-Host "Executing: $($tweak.Name)" -ForegroundColor Yellow
    Write-Host "Category: $($tweak.Category)" -ForegroundColor Yellow
    Write-Host "-" * 80
    
    try {
        # Create registry backup before making changes
        if ($tweak.Category -notin @("Settings", "System Tools")) {
            Backup-Registry "HKCU:\Software\Microsoft\Windows\CurrentVersion"
            Backup-Registry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"
        }
        
        & $tweak.Action
        Write-Host "`nSUCCESS: Operation completed" -ForegroundColor Green
        Write-Log "Executed: $($tweak.Name)" -type "SUCCESS"
    } 
    catch {
        Write-Host "`nERROR: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log "Failed: $($tweak.Name) - $($_.Exception.Message)" -type "ERROR"
    }
    
    Read-Host "`nPress Enter to continue..."
}

function Restore-System {
    Show-Header
    Write-Host "SYSTEM RESTORE OPTIONS" -ForegroundColor $themes[$CurrentTheme].Primary
    Write-Host "1. Restore from registry backups"
    Write-Host "2. Reset Windows Update components"
    Write-Host "3. Restore default services"
    Write-Host "4. Restore default power plan"
    Write-Host "5. Back to main menu"
    
    $choice = Read-Host "`nSelect restore option"
    
    switch ($choice) {
        "1" {
            if (Test-Path $backupDir) {
                $backups = Get-ChildItem $backupDir -Filter *.reg
                if ($backups) {
                    foreach ($backup in $backups) {
                        try {
                            Write-Host "Restoring $($backup.Name)..."
                            Start-Process -FilePath "reg.exe" -ArgumentList "import `"$($backup.FullName)`"" -Wait -NoNewWindow
                            Write-Log "Restored registry from $($backup.Name)"
                        }
                        catch {
                            Write-Host "Error restoring $($backup.Name): $_" -ForegroundColor Red
                            Write-Log "Error restoring $($backup.Name): $_" -type "ERROR"
                        }
                    }
                    Write-Host "Registry restored from backups" -ForegroundColor Green
                }
                else {
                    Write-Host "No registry backups found" -ForegroundColor Yellow
                }
            }
            else {
                Write-Host "Backup directory not found" -ForegroundColor Yellow
            }
        }
        "2" {
            try {
                Stop-Service wuauserv -Force -ErrorAction Stop
                Stop-Service bits -Force -ErrorAction Stop
                
                Remove-Item "$env:SYSTEMROOT\SoftwareDistribution\*" -Recurse -Force -ErrorAction Stop
                
                Start-Service bits -ErrorAction Stop
                Start-Service wuauserv -ErrorAction Stop
                
                Write-Host "Windows Update components reset" -ForegroundColor Green
                Write-Log "Reset Windows Update components"
            }
            catch {
                Write-Host "Error resetting Windows Update: $_" -ForegroundColor Red
                Write-Log "Error resetting Windows Update: $_" -type "ERROR"
            }
        }
        "3" {
            try {
                $services = Get-Service | Where-Object { $_.StartType -eq "Disabled" }
                foreach ($service in $services) {
                    try {
                        Set-Service -Name $service.Name -StartupType Automatic -ErrorAction SilentlyContinue
                        Write-Log "Reset service $($service.Name) to Automatic"
                    }
                    catch {
                        Write-Log "Error resetting service $($service.Name): $_" -type "ERROR"
                    }
                }
                Write-Host "Services restored to default startup types" -ForegroundColor Green
            }
            catch {
                Write-Host "Error restoring services: $_" -ForegroundColor Red
                Write-Log "Error restoring services: $_" -type "ERROR"
            }
        }
        "4" {
            try {
                powercfg /setactive 381b4222-f694-41f0-9685-ff5bb260df2e | Out-Null  # Balanced power plan
                powercfg /h on | Out-Null
                Write-Host "Restored default power plan" -ForegroundColor Green
                Write-Log "Restored default power plan"
            }
            catch {
                Write-Host "Error restoring power plan: $_" -ForegroundColor Red
                Write-Log "Error restoring power plan: $_" -type "ERROR"
            }
        }
        "5" { return }
        default {
            Write-Host "Invalid option" -ForegroundColor Red
        }
    }
    
    if ($choice -ne "5") {
        Read-Host "`nPress Enter to continue..."
    }
}

# Main execution
try {
    Show-BinaryAnimation
    Show-AsciiLogo
    
    while ($true) {
        $choice = Show-MainMenu
        
        switch -Regex ($choice) {
            "^\d+$" {
                $index = [int]$choice - 1
                $categories = $tweaks.Category | Select-Object -Unique
                if ($index -ge 0 -and $index -lt $categories.Count) {
                    $category = ($categories)[$index]
                    $categoryTweaks = $tweaks | Where-Object { $_.Category -eq $category } | Sort-Object Name
                    
                    Show-Header
                    Write-Host "$category TWEAKS:" -ForegroundColor $themes[$CurrentTheme].Primary
                    for ($i = 0; $i -lt $categoryTweaks.Count; $i++) {
                        Write-Host "$($i+1). $($categoryTweaks[$i].Name)" -ForegroundColor $themes[$CurrentTheme].Primary
                    }
                    Write-Host "0. Back" -ForegroundColor $themes[$CurrentTheme].Primary
                    
                    $tweakChoice = Read-Host "`nSelect tweak"
                    if ($tweakChoice -ne "0") {
                        $tweakIndex = [int]$tweakChoice - 1
                        if ($tweakIndex -ge 0 -and $tweakIndex -lt $categoryTweaks.Count) {
                            if (Confirm-Action "Run $($categoryTweaks[$tweakIndex].Name)") {
                                Invoke-Tweak $categoryTweaks[$tweakIndex]
                            }
                        }
                        else {
                            Write-Host "Invalid selection" -ForegroundColor Red
                            Start-Sleep -Seconds 1
                        }
                    }
                }
                else {
                    Write-Host "Invalid category selection" -ForegroundColor Red
                    Start-Sleep -Seconds 1
                }
            }
            "C" {
                if (Confirm-Action "Run ALL tweaks (this may take several minutes)") {
                    foreach ($tweak in $tweaks) {
                        Invoke-Tweak $tweak
                    }
                }
            }
            "R" { Restore-System }
            "L" { 
                if (Test-Path $logPath) {
                    Start-Process notepad.exe $logPath 
                }
                else {
                    Write-Host "No log file found" -ForegroundColor Yellow
                    Start-Sleep -Seconds 1
                }
            }
            "X" { exit }
            default {
                Write-Host "Invalid option" -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    }
} 
catch {
    Write-Host "Critical error: $_" -ForegroundColor Red
    Write-Log "CRITICAL: $_" -type "ERROR"
    Read-Host "Press Enter to exit"
    exit 1
}
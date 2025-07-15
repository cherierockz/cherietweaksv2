function Red($msg) { Write-Host $msg -ForegroundColor Red }
function Pause { Red "`nPress Enter to continue..."; [void][System.Console]::ReadLine() }
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Red "ERROR: Run as admin!"; Pause; exit }


Red ""
Red "_________   ___ ________________________.___________________________      _____________   _____   ____  __.  _________ ____   ____________  "
Red "\_   ___ \ /   |   \_   _____/\______   \   \_   _____/\__    ___/  \    /  \_   _____/  /  _  \ |    |/ _| /   _____/ \   \ /   /\_____  \ "
Red "/    \  \//    ~    \    __)_  |       _/   ||    __)_   |    |  \   \/\/   /|    __)_  /  /_\  \|      <   \_____  \   \   Y   /  /  ____/ "
Red "\     \___\    Y    /        \ |    |   \   ||        \  |    |   \        / |        \/    |    \    |  \  /        \   \     /  /       \ "
Red " \______  /\___|_  /_______  / |____|_  /___/_______  /  |____|    \__/\  / /_______  /\____|__  /____|__ \/_______  /    \___/   \_______ \"
Red "        \/       \/        \/         \/            \/                  \/          \/         \/        \/        \/                     \/"
Red ""
Red "CHERIETWEAKER V2 - SELECT A TWEAK TO RUN"
Red "DEVELOPED BY CHERIEROCKZ"
Red "================================================================================"
Red ""

$tweaks = @(
@{
    n = 'Remove OneDrive'
    a = {
        $p = Get-AppxPackage -Name 'Microsoft.OneDrive' -ErrorAction SilentlyContinue
        if ($p) {
            Red 'Uninstalling OneDrive...'
            Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
        }
        else {
            Red 'NOTHING TO DELETE: OneDrive'
        }
    }
},
@{
    n = 'Disable Cortana'
    a = {
        $p = Get-AppxPackage -Name 'Microsoft.549981C3F5F10' -ErrorAction SilentlyContinue
        if ($p) {
            Red 'Disabling Cortana...'
            Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
        }
        else {
            Red 'NOTHING TO DELETE: Cortana'
        }
    }
},
@{
    n = 'Disable Telemetry (DiagTrack)'
    a = {
        try {
            $svc = Get-Service -Name 'DiagTrack' -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -ne 'Stopped') {
                Set-Service 'DiagTrack' -StartupType Disabled -ErrorAction SilentlyContinue
                Stop-Service 'DiagTrack' -Force -ErrorAction SilentlyContinue
                Red 'Telemetry Disabled'
            } else { Red 'NOTHING TO DISABLE: DiagTrack' }
        } catch { Red 'NOTHING TO DISABLE: DiagTrack' }
    }
},
@{
    n = 'Clear Temp Files'
    a = {
        $files = Get-ChildItem "$env:TEMP" -Force -ErrorAction SilentlyContinue
        if ($files.Count -gt 0) {
            Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
            Red 'Temp files deleted'
        } else { Red 'NOTHING TO DELETE: Temp files' }
    }
},
@{
    n = 'Empty Recycle Bin'
    a = {
        try {
            $count = (Get-ChildItem "Shell:RecycleBinFolder" -ErrorAction SilentlyContinue).Count
            if ($count -gt 0) {
                Clear-RecycleBin -Force -ErrorAction SilentlyContinue
                Red 'Recycle Bin emptied'
            } else { Red 'NOTHING TO DELETE: Recycle Bin' }
        } catch { Red 'NOTHING TO DELETE: Recycle Bin' }
    }
},
@{
    n = 'Disable Xbox GameBar'
    a = {
        $p = Get-AppxPackage -Name '*XboxGameOverlay*' -ErrorAction SilentlyContinue
        if ($p) {
            Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
            Red 'Xbox GameBar disabled'
        }
        else { Red 'NOTHING TO DELETE: Xbox GameBar' }
    }
},
@{
    n = 'Remove PeopleBar'
    a = {
        $p = Get-AppxPackage -Name 'Microsoft.People' -ErrorAction SilentlyContinue
        if ($p) {
            Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
            Red 'PeopleBar removed'
        }
        else { Red 'NOTHING TO DELETE: PeopleBar' }
    }
},
@{
    n = 'Remove Skype'
    a = {
        $p = Get-AppxPackage -Name 'Microsoft.SkypeApp' -ErrorAction SilentlyContinue
        if ($p) {
            Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
            Red 'Skype removed'
        }
        else { Red 'NOTHING TO DELETE: Skype' }
    }
},
@{
    n = 'Remove Movies & TV'
    a = {
        $p = Get-AppxPackage -Name 'Microsoft.ZuneVideo' -ErrorAction SilentlyContinue
        if ($p) {
            Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
            Red 'Movies & TV removed'
        }
        else { Red 'NOTHING TO DELETE: Movies & TV' }
    }
},
@{
    n = 'Remove Groove Music'
    a = {
        $p = Get-AppxPackage -Name 'Microsoft.ZuneMusic' -ErrorAction SilentlyContinue
        if ($p) {
            Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
            Red 'Groove Music removed'
        }
        else { Red 'NOTHING TO DELETE: Groove Music' }
    }
},
@{
    n = 'Remove Alarms & Clock'
    a = {
        $p = Get-AppxPackage -Name 'Microsoft.WindowsAlarms' -ErrorAction SilentlyContinue
        if ($p) {
            Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
            Red 'Alarms & Clock removed'
        }
        else { Red 'NOTHING TO DELETE: Alarms & Clock' }
    }
},
@{
    n = 'Remove Maps'
    a = {
        $p = Get-AppxPackage -Name 'Microsoft.WindowsMaps' -ErrorAction SilentlyContinue
        if ($p) {
            Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
            Red 'Maps removed'
        }
        else { Red 'NOTHING TO DELETE: Maps' }
    }
},
@{
    n = 'Remove Camera'
    a = {
        $p = Get-AppxPackage -Name 'Microsoft.WindowsCamera' -ErrorAction SilentlyContinue
        if ($p) {
            Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
            Red 'Camera removed'
        }
        else { Red 'NOTHING TO DELETE: Camera' }
    }
},
@{
    n = 'Remove News & Interests'
    a = {
        $reg="HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds"
        try {
            Set-ItemProperty -Path $reg -Name ShellFeedsTaskbarViewMode -Value 2 -ErrorAction SilentlyContinue
            Red 'News & Interests removed'
        } catch { Red 'NOTHING TO DISABLE: News & Interests' }
    }
},
@{
    n = 'Remove Solitaire Collection'
    a = {
        $p = Get-AppxPackage -Name 'Microsoft.MicrosoftSolitaireCollection' -ErrorAction SilentlyContinue
        if ($p) {
            Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
            Red 'Solitaire removed'
        }
        else { Red 'NOTHING TO DELETE: Solitaire' }
    }
},
@{
    n = 'Remove Candy Crush'
    a = {
        $p = Get-AppxPackage -Name '*CandyCrush*' -ErrorAction SilentlyContinue
        if ($p) {
            Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
            Red 'Candy Crush removed'
        }
        else { Red 'NOTHING TO DELETE: Candy Crush' }
    }
},
@{
    n = 'Remove Clipchamp'
    a = {
        $p = Get-AppxPackage -Name 'Microsoft.Clipchamp' -ErrorAction SilentlyContinue
        if ($p) {
            Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
            Red 'Clipchamp removed'
        }
        else { Red 'NOTHING TO DELETE: Clipchamp' }
    }
},
@{
    n = 'Remove Your Phone'
    a = {
        $p = Get-AppxPackage -Name 'Microsoft.YourPhone' -ErrorAction SilentlyContinue
        if ($p) {
            Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
            Red 'Your Phone removed'
        }
        else { Red 'NOTHING TO DELETE: Your Phone' }
    }
},
@{
    n = 'Remove Get Started'
    a = {
        $p = Get-AppxPackage -Name 'Microsoft.Getstarted' -ErrorAction SilentlyContinue
        if ($p) {
            Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
            Red 'Get Started removed'
        }
        else { Red 'NOTHING TO DELETE: Get Started' }
    }
},
@{
    n = 'Remove Weather'
    a = {
        $p = Get-AppxPackage -Name 'Microsoft.BingWeather' -ErrorAction SilentlyContinue
        if ($p) {
            Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
            Red 'Weather removed'
        }
        else { Red 'NOTHING TO DELETE: Weather' }
    }
},
@{
    n = 'Remove Feedback Hub'
    a = {
        $p = Get-AppxPackage -Name 'Microsoft.WindowsFeedbackHub' -ErrorAction SilentlyContinue
        if ($p) {
            Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
            Red 'Feedback Hub removed'
        }
        else { Red 'NOTHING TO DELETE: Feedback Hub' }
    }
},
@{
    n = 'Remove 3D Viewer'
    a = {
        $p = Get-AppxPackage -Name 'Microsoft.Microsoft3DViewer' -ErrorAction SilentlyContinue
        if ($p) {
            Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
            Red '3D Viewer removed'
        }
        else { Red 'NOTHING TO DELETE: 3D Viewer' }
    }
},
@{
    n = 'Remove Paint 3D'
    a = {
        $p = Get-AppxPackage -Name 'Microsoft.MSPaint' -ErrorAction SilentlyContinue
        if ($p) {
            Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
            Red 'Paint 3D removed'
        }
        else { Red 'NOTHING TO DELETE: Paint 3D' }
    }
},
@{
    n = 'Disable Windows Search'
    a = {
        try {
            $svc = Get-Service -Name 'WSearch' -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -ne 'Stopped') {
                Stop-Service WSearch -Force -ErrorAction SilentlyContinue
                Set-Service WSearch -StartupType Disabled -ErrorAction SilentlyContinue
                Red 'Windows Search disabled'
            } else { Red 'NOTHING TO DISABLE: Windows Search' }
        } catch { Red 'NOTHING TO DISABLE: Windows Search' }
    }
},
@{
    n = 'Disable SmartScreen'
    a = {
        $reg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
        try {
            $current = (Get-ItemProperty -Path $reg -Name SmartScreenEnabled -ErrorAction SilentlyContinue).SmartScreenEnabled
            if ($current -ne "Off") {
                Set-ItemProperty -Path $reg -Name SmartScreenEnabled -Value "Off"
                Red 'SmartScreen disabled'
            } else { Red 'NOTHING TO DISABLE: SmartScreen' }
        } catch { Red 'NOTHING TO DISABLE: SmartScreen' }
    }
},
@{
    n = 'Disable Location'
    a = {
        $reg = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"
        try {
            $current = (Get-ItemProperty -Path $reg -Name Status -ErrorAction SilentlyContinue).Status
            if ($current -ne 0) {
                Set-ItemProperty -Path $reg -Name Status -Value 0
                Red 'Location disabled'
            } else { Red 'NOTHING TO DISABLE: Location' }
        } catch { Red 'NOTHING TO DISABLE: Location' }
    }
},
@{
    n = 'Disable Error Reporting'
    a = {
        try {
            $svc = Get-Service -Name 'WerSvc' -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -ne 'Stopped') {
                Stop-Service WerSvc -Force -ErrorAction SilentlyContinue
                Set-Service WerSvc -StartupType Disabled -ErrorAction SilentlyContinue
                Red 'Error Reporting disabled'
            } else { Red 'NOTHING TO DISABLE: WerSvc' }
        } catch { Red 'NOTHING TO DISABLE: WerSvc' }
    }
},
@{
    n = 'Disable Meet Now'
    a = {
        $p = Get-AppxPackage -Name 'Microsoft.MicrosoftMeetings' -ErrorAction SilentlyContinue
        if ($p) {
            Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
            Red 'Meet Now removed'
        }
        else { Red 'NOTHING TO DELETE: Meet Now' }
    }
},
@{
    n = 'Remove Microsoft Edge'
    a = {
        $path = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application"
        if (Test-Path $path) {
            $exe = Get-ChildItem "$path\*\Installer\setup.exe" -Recurse -ErrorAction SilentlyContinue
            if ($exe) {
                foreach ($e in $exe) {
                    Start-Process $e.FullName "--uninstall --force-uninstall --system-level" -Wait
                }
                Red 'Edge removed'
            } else { Red 'Edge uninstaller not found' }
        } else { Red 'NOTHING TO DELETE: Edge' }
    }
},
@{
    n = 'Disable Widgets'
    a = {
        $reg="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        try {
            Set-ItemProperty -Path $reg -Name TaskbarDa -Value 0 -ErrorAction SilentlyContinue
            Red 'Widgets disabled'
        } catch { Red 'NOTHING TO DISABLE: Widgets' }
    }
},
@{
    n = 'Remove OneNote'
    a = {
        $p=Get-AppxPackage -Name 'Microsoft.Office.OneNote' -ErrorAction SilentlyContinue
        if ($p) {
            Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
            Red 'OneNote removed'
        }
        else { Red 'NOTHING TO DELETE: OneNote' }
    }
},
@{
    n = 'Remove Bing News'
    a = {
        $p=Get-AppxPackage -Name 'Microsoft.BingNews' -ErrorAction SilentlyContinue
        if ($p) {
            Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
            Red 'Bing News removed'
        }
        else { Red 'NOTHING TO DELETE: Bing News' }
    }
},
@{
    n = 'Remove To Do'
    a = {
        $p=Get-AppxPackage -Name 'Microsoft.Todos' -ErrorAction SilentlyContinue
        if ($p) {
            Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
            Red 'To Do removed'
        }
        else { Red 'NOTHING TO DELETE: To Do' }
    }
},
@{
    n = 'Remove Weather Widgets'
    a = {
        $p=Get-AppxPackage -Name 'Microsoft.BingWeather' -ErrorAction SilentlyContinue
        if ($p) {
            Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
            Red 'Weather Widgets removed'
        }
        else { Red 'NOTHING TO DELETE: Weather Widgets' }
    }
},
@{
    n = 'Remove Messaging'
    a = {
        $p=Get-AppxPackage -Name 'Microsoft.Messaging' -ErrorAction SilentlyContinue
        if ($p) {
            Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
            Red 'Messaging removed'
        }
        else { Red 'NOTHING TO DELETE: Messaging' }
    }
}
)

do {
    Red "Type a number to run a tweak, or type part of a tweak name to search."
    for ($i=0; $i -lt $tweaks.Count; $i++) { Red "$($i+1). $($tweaks[$i].n)" }
    Red "0. All tweaks"
    Red "-1. Exit"
    $input = Read-Host "Choose a tweak (number, keyword, -1=exit)"

    if ($input -eq '-1') { break }
    elseif ($input -eq '0') { foreach ($t in $tweaks) { & $t.a } }
    elseif ($input -match '^\d+$' -and [int]$input -gt 0 -and [int]$input -le $tweaks.Count) {
        & $tweaks[[int]$input-1].a
    }
    else {
   
        $matches = @()
        for ($i=0; $i -lt $tweaks.Count; $i++) {
            if ($tweaks[$i].n -like "*$input*") { $matches += [PSCustomObject]@{ Index = $i+1; Name = $tweaks[$i].n } }
        }
        if ($matches.Count -eq 0) { Red "No tweaks found matching '$input'." }
        else {
            Red "Matches:"
            $matches | ForEach-Object { Red "$($_.Index). $($_.Name)" }
        }
    }
    Pause
} while ($true)

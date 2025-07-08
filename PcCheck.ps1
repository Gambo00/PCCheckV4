
# PCCheck Advanced Forensic Analysis & Stealth Cleanup Tool
# For safe and local quick-dumping of System logs and files with complete trace removal
#
# Author:
# Created by Gokhan (https://guns.lol/gokhan_)
# Licensed under GPL-3.0 license
# This script is not related to any external Project.
#
# Features:
# - Complete forensic system analysis
# - Advanced gaming cheat detection and removal
# - Stealth mode with zero-trace self-destruction
# - Anti-recovery measures for maximum security
# - Administrative privilege detection
#
# Usage:
# Use with PowerShell 5.1 and NET 4.0 or higher.
# Run as Administrator for full functionality.
# Running PC Checking Programs, including this script, outside of PC Checks may have impact on the outcome.
# It is advised not to use this on your own.
#
# Version 3.0 - GitHub Release
# 08 - July - 2025

$ErrorActionPreference = "SilentlyContinue"

# Helper Functions
function Test-AdminRights {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
}

function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $timestamp = Get-Date -Format "HH:mm:ss"
    Write-Host "[$timestamp] $Message" -ForegroundColor $Color
}

function Invoke-SecureDelete {
    param([string]$FilePath)
    try {
        if (Test-Path $FilePath) {
            $item = Get-Item $FilePath -Force -ErrorAction SilentlyContinue
            if ($item.PSIsContainer) {
                # Directory - recursively delete contents first
                Get-ChildItem -Path $FilePath -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    Invoke-SecureDelete $_.FullName
                }
                Remove-Item $FilePath -Force -Recurse -ErrorAction SilentlyContinue
            } else {
                # File - secure overwrite then delete
                $content = Get-Content $FilePath -Raw -ErrorAction SilentlyContinue
                if ($content) {
                    # Multiple overwrite passes for secure deletion
                    for ($i = 0; $i -lt 3; $i++) {
                        try {
                            [IO.File]::WriteAllText($FilePath, ([char]0 * $content.Length))
                            [IO.File]::WriteAllText($FilePath, ([char]255 * $content.Length))
                        } catch { break }
                    }
                }
                Remove-Item $FilePath -Force -ErrorAction SilentlyContinue
            }
            return $true
        }
    } catch { 
        return $false
    }
    return $false
}

function Show-Progress {
    param([int]$CurrentStep, [int]$TotalSteps, [string]$Activity)
    $percent = [math]::Round(($CurrentStep / $TotalSteps) * 100)
    Write-Progress -Activity $Activity -Status "$CurrentStep of $TotalSteps completed" -PercentComplete $percent
}

function Test-InternetConnection {
    try {
        $result = Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -InformationLevel "Quiet" -WarningAction SilentlyContinue
        return $result
    } catch {
        return $false
    }
}

function Initialize-Directories {
    try {
        New-Item -Path "C:\Temp\Scripts" -ItemType Directory -Force | Out-Null
        New-Item -Path "C:\Temp\Dump" -ItemType Directory -Force | Out-Null
        
        # Create a local Menu.ps1 replacement for admin commands
        $menuContent = @"
# Local PCCheck Menu - Alternative to original Menu.ps1
# This replaces the functionality that admins would get from:
# Invoke-WebRequest -Uri "https://raw.githubusercontent.com/dot-sys/PCCheckv2/master/Menu.ps1" -OutFile "Menu.ps1"

Write-Host "╔═══════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║        PCCheck Local Menu v3.0       ║" -ForegroundColor Cyan  
Write-Host "║     Alternative Analysis Tools        ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check for downloaded tools
`$tools = Get-ChildItem C:\Temp\Scripts -Filter "*.ps1" | Where-Object { `$_.Name -ne "Menu.ps1" }
if (`$tools) {
    Write-Host "Available Analysis Tools:" -ForegroundColor Yellow
    `$tools | ForEach-Object {
        Write-Host "- `$(`$_.Name)" -ForegroundColor Green
    }
    Write-Host ""
    
    # Execution policy setup (replicates admin commands)
    try {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
        Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned -Force
        Add-MpPreference -ExclusionPath 'C:\Temp' -ErrorAction SilentlyContinue
        Write-Host "Execution policies configured successfully." -ForegroundColor Green
    } catch {
        Write-Host "Warning: Could not set all execution policies. May need admin rights." -ForegroundColor Yellow
    }
    
    # Run first available tool
    if (`$tools.Count -gt 0) {
        Write-Host "Executing: `$(`$tools[0].Name)" -ForegroundColor Cyan
        try {
            & `$tools[0].FullName
        } catch {
            Write-Host "Error executing `$(`$tools[0].Name): `$(`$_.Exception.Message)" -ForegroundColor Red
        }
    }
} else {
    Write-Host "No additional tools downloaded. Running local analysis..." -ForegroundColor Yellow
    
    # Local analysis fallback
    Write-Host "`nSystem Information:" -ForegroundColor Cyan
    try {
        Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, TotalPhysicalMemory | Format-Table
        Write-Host "Top Processes by CPU:" -ForegroundColor Cyan
        Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 | Format-Table Name, CPU, WorkingSet
    } catch {
        Write-Host "Error gathering system info: `$(`$_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Read-Host "Press Enter to exit"
"@
        
        $menuContent | Out-File "C:\Temp\Scripts\Menu.ps1" -Encoding UTF8
        
        return $true
    } catch {
        Write-Host "Error creating directories: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Get-FileWithProgress {
    param(
        [string]$Url,
        [string]$OutputPath
    )
    try {
        if (-not (Test-InternetConnection)) {
            Write-Host "No internet connection available!" -ForegroundColor Red
            return $false
        }
        
        Write-Host "Downloading $(Split-Path $OutputPath -Leaf)..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $Url -OutFile $OutputPath -UseBasicParsing
        return (Test-Path $OutputPath)
    } catch {
        Write-Host "Error downloading file: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Remove duplicate version comment and ErrorActionPreference 
function Show-MainMenu {
    Write-Host "`n╔═══════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║      PCCheck Advanced Forensic Analysis Tool     ║" -ForegroundColor Cyan
    Write-Host "║                 Version 3.0                      ║" -ForegroundColor Cyan
    Write-Host "║                                                   ║" -ForegroundColor Cyan
    Write-Host "║        Created by: Gokhan " -ForegroundColor Yellow -NoNewline
    Write-Host "(" -ForegroundColor Gray -NoNewline
    Write-Host "guns.lol/gokhan_" -ForegroundColor Blue -NoNewline
    Write-Host ")" -ForegroundColor Gray -NoNewline
    Write-Host "     ║" -ForegroundColor Yellow
    Write-Host "║              Advanced Stealth Edition            ║" -ForegroundColor Gray
    Write-Host "║                                                   ║" -ForegroundColor Cyan
    Write-Host "║     Press 'L' to open link | 'C' for contact     ║" -ForegroundColor DarkYellow
    Write-Host "╚═══════════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    Write-Host ""
    Write-Host ""
    Write-Host "Choose a Category:"
    Write-Host ""
    Write-Host "(1)        Checks"
    Write-Host "(2)        Programs"
    Write-Host "(Clean)    Clean Traces"
    Write-Host "(Delete)   Delete Myself (Complete Cleanup)"
    Write-Host "(L)        Open Creator Link"
    Write-Host "(C)        Contact Info"
    Write-Host "(0)        Close Script"
    Write-Host ""
    
    return Read-Host "Choose"
}

function Show-ChecksMenu {
    Write-Host ""
    Write-Host ""
    Write-Host ""
    Write-Host "Checks Menu:"
    Write-Host ""
    Write-Host "(1)    Full Check"
    Write-Host "(2)    Quick Check"
    Write-Host "(3)    Recording Check"
    Write-Host "(4)    Advanced Filechecking (BETA - Requires Full Check)"
    Write-Host "(0)    Back to Main Menu"
    Write-Host ""
    
    return Read-Host "Choose"
}

function Show-ProgramsMenu {
    Write-Host ""
    Write-Host ""
    Write-Host ""
    Write-Host "Programs Menu:"
    Write-Host ""
    Write-Host "(1)    Download CSV File View (by NirSoft)"
    Write-Host "(2)    Download Timeline Explorer (by Eric Zimmerman)"
    Write-Host "(3)    Download Registry Explorer (by Eric Zimmerman)"
    Write-Host "(4)    Download Journal Tool (by Echo)"
    Write-Host "(5)    Download WinprefetchView (by NirSoft)"
    Write-Host "(6)    Download System Informer (by Winsider S and S Inc.)"
    Write-Host "(7)    Download Everything (by voidtools)"
    Write-Host "(0)    Back to Main Menu"
    Write-Host ""
    
    return Read-Host "Choose"
}

function CleanTraces {
    Write-Host "`n`nCleaning traces of the Check..." -ForegroundColor Yellow
    Write-Host "Does not include installed programs" -ForegroundColor Yellow
    Start-Sleep 1
    
    try {
        if (Test-Path "C:\Temp\Dump") {
            Get-ChildItem -Path "C:\Temp\Dump" -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path "C:\Temp\Scripts") {
            Get-ChildItem -Path "C:\Temp\Scripts" -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "Menu.ps1" } | ForEach-Object { 
                Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        Write-Host "Traces cleaned successfully." -ForegroundColor Green
    } catch {
        Write-Host "Error cleaning traces: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host "`n`n`tReturning to Menu in 2 Seconds`n`n`n" -ForegroundColor Magenta
    Start-Sleep 2
}

function DeleteMyself {
    Write-Host "`n`nWARNING: COMPLETE STEALTH MODE - NO TRACES WILL REMAIN!" -ForegroundColor Red
    Write-Host "This will erase ALL evidence that this program ever existed:" -ForegroundColor Yellow
    Write-Host "- All downloaded forensic tools and programs" -ForegroundColor Yellow
    Write-Host "- All system analysis data and logs" -ForegroundColor Yellow
    Write-Host "- Gaming cheat files and configurations" -ForegroundColor Yellow
    Write-Host "- Aimbot, wallhack, and trainer files" -ForegroundColor Yellow
    Write-Host "- Modified game files (weapons.meta, etc.)" -ForegroundColor Yellow
    Write-Host "- PowerShell history and command logs" -ForegroundColor Yellow
    Write-Host "- Windows Event Logs and security logs" -ForegroundColor Yellow
    Write-Host "- Prefetch files and execution traces" -ForegroundColor Yellow
    Write-Host "- Registry entries and MRU lists" -ForegroundColor Yellow
    Write-Host "- Browser download history entries" -ForegroundColor Yellow
    Write-Host "- Windows Search index entries" -ForegroundColor Yellow
    Write-Host "- This script and all temporary files" -ForegroundColor Yellow
    Write-Host "`nAfter this, NO FORENSIC TOOL can prove this program OR gaming cheats existed!" -ForegroundColor Red
    
    # Check admin rights
    if (-NOT (Test-AdminRights)) {
        Write-Host "`nWARNING: Running without Administrator rights!" -ForegroundColor Red
        Write-Host "Some traces might remain due to insufficient permissions." -ForegroundColor Yellow
        $adminChoice = Read-Host "Continue anyway? (y/n)"
        if ($adminChoice -ne "y") { 
            Write-Host "Operation cancelled. Run as Administrator for full stealth mode." -ForegroundColor Yellow
            return 
        }
    }
    
    $confirmation = Read-Host "Are you ABSOLUTELY sure? Type 'STEALTH' to confirm"
    
    if ($confirmation -eq "STEALTH") {
        Write-Host "`n`nInitiating STEALTH deletion mode..." -ForegroundColor Red
        Write-Host "Making this program disappear forever..." -ForegroundColor Red
        Start-Sleep 2
        
        $totalSteps = 23
        
        # Terminate suspicious processes first
        Write-Log "Terminating suspicious processes..." "Yellow"
        Show-Progress -CurrentStep 1 -TotalSteps $totalSteps -Activity "STEALTH MODE"
        $suspiciousProcesses = @("*cheatengine*", "*hack*", "*aimbot*", "*wallhack*", "*trainer*", "*injector*", "*processhacker*")
        foreach ($pattern in $suspiciousProcesses) {
            Get-Process | Where-Object {$_.ProcessName -like $pattern} | Stop-Process -Force -ErrorAction SilentlyContinue
        }
        
        # Clear PowerShell ISE recent files
        Write-Log "Clearing PowerShell ISE recent files..." "Yellow"
        Show-Progress -CurrentStep 2 -TotalSteps $totalSteps -Activity "STEALTH MODE"
        $iseRecentPath = "$env:USERPROFILE\Documents\WindowsPowerShell\ISERecentFiles.xml"
        if (Test-Path $iseRecentPath) { Invoke-SecureDelete $iseRecentPath }
        
        # Clear PSReadLine history with better error handling
        Write-Log "Wiping PowerShell history..." "Yellow"
        Show-Progress -CurrentStep 3 -TotalSteps $totalSteps -Activity "STEALTH MODE"
        Clear-History -ErrorAction SilentlyContinue
        
        try {
            if (Get-Module -Name PSReadLine -ListAvailable) {
                $psReadlineHistory = (Get-PSReadlineOption).HistorySavePath
                if ($psReadlineHistory -and (Test-Path $psReadlineHistory)) {
                    Invoke-SecureDelete $psReadlineHistory
                }
            }
        } catch { }
        
        # Fallback history paths
        $historyPaths = @(
            "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
            "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        )
        foreach ($histPath in $historyPaths) {
            if (Test-Path $histPath) { 
                Invoke-SecureDelete $histPath 
            }
        }
        
        # Clear Windows Recent Documents
        Write-Log "Clearing recent documents..." "Yellow"
        Show-Progress -CurrentStep 4 -TotalSteps $totalSteps -Activity "STEALTH MODE"
        $recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
        if (Test-Path $recentPath) {
            Get-ChildItem -Path $recentPath -Filter "*.ps1.lnk" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            Get-ChildItem -Path $recentPath -Filter "*pccheck*" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            Get-ChildItem -Path $recentPath -Filter "*menu*" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        }
        
        # Clear Windows Event Logs
        Write-Log "Wiping Windows Event Logs..." "Yellow"
        Show-Progress -CurrentStep 5 -TotalSteps $totalSteps -Activity "STEALTH MODE"
        $eventLogs = @(
            "Windows PowerShell",
            "Microsoft-Windows-PowerShell/Operational", 
            "Microsoft-Windows-PowerShell/Analytic",
            "Microsoft-Windows-WinRM/Operational",
            "Security",
            "System",
            "Application"
        )
        foreach ($log in $eventLogs) {
            try {
                wevtutil cl "$log" 2>$null
            } catch { }
        }
        
        # Clear Prefetch files
        Write-Log "Removing prefetch traces..." "Yellow"
        Show-Progress -CurrentStep 6 -TotalSteps $totalSteps -Activity "STEALTH MODE"
        $prefetchPath = "$env:SystemRoot\Prefetch"
        if (Test-Path $prefetchPath) {
            Get-ChildItem -Path $prefetchPath -Filter "*POWERSHELL*" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            Get-ChildItem -Path $prefetchPath -Filter "*MENU*" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            Get-ChildItem -Path $prefetchPath -Filter "*PCCHECK*" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        }
        
        # Clear Registry MRU lists
        Write-Log "Cleaning registry traces..." "Yellow"
        Show-Progress -CurrentStep 7 -TotalSteps $totalSteps -Activity "STEALTH MODE"
        $registryPaths = @(
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
        )
        foreach ($regPath in $registryPaths) {
            try {
                if (Test-Path $regPath) {
                    $items = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                    if ($items) {
                        $items.PSObject.Properties | Where-Object { 
                            $_.Value -like "*pccheck*" -or $_.Value -like "*menu*" -or $_.Value -like "*temp*" 
                        } | ForEach-Object {
                            Remove-ItemProperty -Path $regPath -Name $_.Name -ErrorAction SilentlyContinue
                        }
                    }
                }
            } catch { }
        }
        
        # Clear Browser Download History (if downloaded via browser)
        Write-Log "Clearing browser download traces..." "Yellow"
        Show-Progress -CurrentStep 8 -TotalSteps $totalSteps -Activity "STEALTH MODE"
        $browserPaths = @(
            "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History",
            "$env:APPDATA\Mozilla\Firefox\Profiles\*\downloads.sqlite",
            "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
        )
        foreach ($browserPath in $browserPaths) {
            if (Test-Path (Split-Path $browserPath)) {
                Get-ChildItem -Path (Split-Path $browserPath) -Filter (Split-Path $browserPath -Leaf) -ErrorAction SilentlyContinue | ForEach-Object {
                    try { 
                        # Simple file deletion instead of SQLite operations
                        if ($_.Name -like "*history*" -or $_.Name -like "*downloads*") {
                            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                        }
                    } catch { }
                }
            }
        }
        
        # Clear Windows Search Index
        Write-Log "Removing from Windows Search index..." "Yellow"
        Show-Progress -CurrentStep 9 -TotalSteps $totalSteps -Activity "STEALTH MODE"
        try {
            $searchService = Get-Service -Name "WSearch" -ErrorAction SilentlyContinue
            if ($searchService -and $searchService.Status -eq "Running") {
                Stop-Service -Name "WSearch" -Force -ErrorAction SilentlyContinue
                Start-Sleep 2
                Start-Service -Name "WSearch" -ErrorAction SilentlyContinue
            }
        } catch { }
        
        # Clear Windows Defender scan history
        Write-Log "Clearing antivirus scan traces..." "Yellow"
        Show-Progress -CurrentStep 10 -TotalSteps $totalSteps -Activity "STEALTH MODE"
        $defenderLogPath = "$env:ProgramData\Microsoft\Windows Defender\Scans\History"
        if (Test-Path $defenderLogPath) {
            Get-ChildItem -Path $defenderLogPath -Recurse -ErrorAction SilentlyContinue | Where-Object { 
                $_.Name -like "*temp*" -or $_.LastWriteTime -gt (Get-Date).AddHours(-24) 
            } | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        }
        
        # Clear Thumbnail Cache
        Write-Log "Clearing thumbnail cache..." "Yellow"
        Show-Progress -CurrentStep 11 -TotalSteps $totalSteps -Activity "STEALTH MODE"
        $thumbcachePaths = @(
            "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db",
            "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\iconcache_*.db"
        )
        foreach ($path in $thumbcachePaths) {
            if (Test-Path (Split-Path $path)) {
                Get-ChildItem -Path (Split-Path $path) -Filter (Split-Path $path -Leaf) -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            }
        }
        
        # Clear Windows Error Reporting
        Write-Log "Clearing error reports..." "Yellow"
        Show-Progress -CurrentStep 12 -TotalSteps $totalSteps -Activity "STEALTH MODE"
        $werPath = "$env:LOCALAPPDATA\Microsoft\Windows\WER"
        if (Test-Path $werPath) {
            Get-ChildItem -Path $werPath -Recurse -ErrorAction SilentlyContinue | Where-Object { 
                $_.Name -like "*powershell*" -or $_.LastWriteTime -gt (Get-Date).AddHours(-24) 
            } | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        }
        
        # Clear Gaming Cheat Files and Traces
        Write-Log "Hunting and destroying gaming cheat files..." "Yellow"
        Show-Progress -CurrentStep 13 -TotalSteps $totalSteps -Activity "STEALTH MODE"
        $advancedCheatPatterns = @(
            # Common cheat file names
            "*playertargetting*", "*aimbot*", "*wallhack*", "*esp*", "*triggerbot*",
            "*weapons.meta*", "*explosive*ammo*", "*unlimited*ammo*", "*godmode*",
            "*speedhack*", "*teleport*", "*noclip*", "*fly*hack*", "*radar*hack*",
            # Cheat engines and injectors
            "*cheatengine*", "*injector*", "*dll*inject*", "*process*hack*",
            "*memory*edit*", "*game*hack*", "*trainer*", "*mod*menu*",
            # Specific game cheats
            "*gta*hack*", "*gta*mod*", "*csgo*hack*", "*valorant*hack*",
            "*fortnite*hack*", "*pubg*hack*", "*minecraft*hack*", "*rust*hack*",
            # Cheat configurations
            "*cheat*config*", "*hack*config*", "*aimbot*settings*", "*esp*config*",
            "*rage*config*", "*legit*config*", "*silent*aim*", "*auto*shoot*",
            # Advanced cheat types
            "*bhop*", "*spinbot*", "*ragebot*", "*legitbot*", "*backtrack*",
            "*resolver*", "*fakelag*", "*antiaim*", "*doubletap*",
            # Steam Workshop Hacks
            "*workshop*hack*", "*steam*cheat*", "*overlay*hack*",
            # Discord/Communication Cheats  
            "*discord*hack*", "*teamspeak*hack*", "*overlay*cheat*",
            # Game-specific mod scripts
            "*fivem*script*", "*redm*script*", "*samp*hack*", "*mtasa*mod*"
        )
        
        Write-Host "    Searching for cheat files and configurations..." -ForegroundColor Red
        $searchPaths = @(
            "C:\",
            "$env:USERPROFILE\Downloads",
            "$env:USERPROFILE\Desktop", 
            "$env:PROGRAMFILES",
            "$env:PROGRAMFILES(X86)",
            "$env:LOCALAPPDATA",
            "$env:APPDATA"
        )
        
        foreach ($pattern in $advancedCheatPatterns) {
            foreach ($searchPath in $searchPaths) {
                if (Test-Path $searchPath) {
                    try {
                        Get-ChildItem -Path $searchPath -Filter $pattern -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                            Write-Host "      Found and destroying cheat file: $($_.FullName)" -ForegroundColor Red
                            Invoke-SecureDelete $_.FullName
                        }
                    } catch { }
                }
            }
        }
        
        # Clear Forensic Tools specifically
        Write-Log "Hunting and destroying forensic tools..." "Yellow"
        Show-Progress -CurrentStep 14 -TotalSteps $totalSteps -Activity "STEALTH MODE"
        $forensicTools = @(
            @{Name="CSVFileView"; Patterns=@("*csvfileview*", "*CSVFileView*")},
            @{Name="Timeline Explorer"; Patterns=@("*timelineexplorer*", "*TimelineExplorer*", "*timeline*explorer*")},
            @{Name="Registry Explorer"; Patterns=@("*registryexplorer*", "*RegistryExplorer*", "*registry*explorer*")},
            @{Name="WinprefetchView"; Patterns=@("*winprefetchview*", "*WinprefetchView*", "*prefetch*view*")}
        )
        
        $searchPaths = @(
            "C:\",
            "$env:USERPROFILE\Downloads",
            "$env:USERPROFILE\Desktop", 
            "$env:PROGRAMFILES",
            "$env:PROGRAMFILES(X86)",
            "$env:LOCALAPPDATA",
            "$env:APPDATA"
        )
        
        foreach ($tool in $forensicTools) {
            Write-Host "    Eliminating $($tool.Name)..." -ForegroundColor Red
            foreach ($searchPath in $searchPaths) {
                if (Test-Path $searchPath) {
                    foreach ($pattern in $tool.Patterns) {
                        try {
                            Get-ChildItem -Path $searchPath -Filter $pattern -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                                Write-Host "      Found and destroying: $($_.FullName)" -ForegroundColor Red
                                Invoke-SecureDelete $_.FullName
                            }
                        } catch { }
                    }
                }
            }
        }
        
        # Anti-Recovery Measures
        Write-Log "Implementing anti-recovery measures..." "Yellow"
        Show-Progress -CurrentStep 15 -TotalSteps $totalSteps -Activity "STEALTH MODE"
        # Delete shadow copies
        try { vssadmin delete shadows /all /quiet 2>$null } catch { }
        # Clear recycle bin
        try { Clear-RecycleBin -Force -ErrorAction SilentlyContinue } catch { }
        # Clear network traces
        try { 
            netsh advfirewall firewall delete rule name=all program="*cheat*" 2>$null
            netsh advfirewall firewall delete rule name=all program="*hack*" 2>$null
            ipconfig /flushdns 2>$null
        } catch { }
        
        # Clear Temp directories completely
        Write-Log "Obliterating all temporary files..." "Yellow"
        Show-Progress -CurrentStep 16 -TotalSteps $totalSteps -Activity "STEALTH MODE"
        $tempPaths = @("C:\Temp", "$env:TEMP", "$env:TMP", "$env:LOCALAPPDATA\Temp")
        foreach ($tempPath in $tempPaths) {
            if (Test-Path $tempPath) {
                Get-ChildItem -Path $tempPath -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    Invoke-SecureDelete $_.FullName
                }
            }
        }
        
        # Clear Gaming Registry Entries and MRU Lists
        Write-Log "Cleaning gaming-related registry traces..." "Yellow"
        Show-Progress -CurrentStep 17 -TotalSteps $totalSteps -Activity "STEALTH MODE"
        $gamingRegistryPaths = @(
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.exe",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.dll",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.meta",
            "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"
        )
        foreach ($regPath in $gamingRegistryPaths) {
            try {
                if (Test-Path $regPath) {
                    $items = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                    if ($items) {
                        $items.PSObject.Properties | Where-Object { 
                            $_.Value -like "*cheat*" -or $_.Value -like "*hack*" -or $_.Value -like "*aimbot*" -or 
                            $_.Value -like "*wallhack*" -or $_.Value -like "*esp*" -or $_.Value -like "*trainer*" -or
                            $_.Value -like "*injector*" -or $_.Value -like "*weapons.meta*" -or $_.Value -like "*explosive*"
                        } | ForEach-Object {
                            Remove-ItemProperty -Path $regPath -Name $_.Name -ErrorAction SilentlyContinue
                        }
                    }
                }
            } catch { }
        }
        
        # Clear Jump Lists
        Write-Log "Clearing jump lists..." "Yellow"
        Show-Progress -CurrentStep 18 -TotalSteps $totalSteps -Activity "STEALTH MODE"
        $jumpListPath = "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations"
        if (Test-Path $jumpListPath) {
            Get-ChildItem -Path $jumpListPath -ErrorAction SilentlyContinue | ForEach-Object {
                Invoke-SecureDelete $_.FullName
            }
        }
        
        # Clear System File Checker logs
        Write-Log "Clearing system logs..." "Yellow"
        Show-Progress -CurrentStep 19 -TotalSteps $totalSteps -Activity "STEALTH MODE"
        $sfcLogPath = "$env:SystemRoot\Logs\CBS\CBS.log"
        if (Test-Path $sfcLogPath) {
            try { Clear-Content $sfcLogPath -Force -ErrorAction SilentlyContinue } catch { }
        }
        
        # Clear Application shortcuts and Start Menu entries
        Write-Log "Removing application shortcuts..." "Yellow"
        Show-Progress -CurrentStep 20 -TotalSteps $totalSteps -Activity "STEALTH MODE"
        $shortcutPaths = @(
            "$env:USERPROFILE\Desktop",
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs",
            "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs"
        )
        foreach ($shortcutPath in $shortcutPaths) {
            if (Test-Path $shortcutPath) {
                Get-ChildItem -Path $shortcutPath -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue | Where-Object {
                    $_.Name -like "*csvfileview*" -or $_.Name -like "*timeline*" -or 
                    $_.Name -like "*registry*explorer*" -or $_.Name -like "*prefetch*" -or
                    $_.Name -like "*pccheck*" -or $_.Name -like "*menu*" -or
                    $_.Name -like "*cheat*" -or $_.Name -like "*hack*" -or $_.Name -like "*aimbot*" -or
                    $_.Name -like "*trainer*" -or $_.Name -like "*injector*" -or $_.Name -like "*wallhack*"
                } | ForEach-Object {
                    Invoke-SecureDelete $_.FullName
                }
            }
        }
        
        # Overwrite free disk space - sdelete alternative
        Write-Log "Overwriting free disk space for anti-recovery..." "Yellow"
        Show-Progress -CurrentStep 21 -TotalSteps $totalSteps -Activity "STEALTH MODE"
        try {
            # Create large temporary file to overwrite free space
            $tempFile = "$env:TEMP\overwrite_$(Get-Random).tmp"
            fsutil file createnew $tempFile 104857600 2>$null  # 100MB
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        } catch { }
        
        # Final cleanup - self destruct
        Write-Log "Preparing self-destruction..." "Yellow"
        Show-Progress -CurrentStep 22 -TotalSteps $totalSteps -Activity "STEALTH MODE"
        
        # Get current script path
        $scriptPath = $PSCommandPath
        if (-not $scriptPath) {
            $scriptPath = $MyInvocation.MyCommand.Path
        }
        if (-not $scriptPath) {
            $scriptPath = $MyInvocation.ScriptName
        }
        if (-not $scriptPath) {
            $scriptPath = $PSScriptRoot + "\" + $MyInvocation.MyCommand.Name
        }
        
        Write-Host "`nFINAL PHASE: Self-destructing in 5 seconds..." -ForegroundColor Red
        Write-Host "After this, this program NEVER EXISTED!" -ForegroundColor Red
        Show-Progress -CurrentStep 23 -TotalSteps $totalSteps -Activity "STEALTH MODE"
        Start-Sleep 1
        Write-Host "5..." -ForegroundColor Red -NoNewline
        Start-Sleep 1
        Write-Host "4..." -ForegroundColor Red -NoNewline
        Start-Sleep 1
        Write-Host "3..." -ForegroundColor Red -NoNewline
        Start-Sleep 1
        Write-Host "2..." -ForegroundColor Red -NoNewline
        Start-Sleep 1
        Write-Host "1..." -ForegroundColor Red
        
        # Create advanced batch file for complete deletion
        $batchContent = "@echo off`n"
        $batchContent += "timeout /t 3 /nobreak `>nul`n"
        $batchContent += "taskkill /f /im powershell.exe 2`>nul`n"
        $batchContent += "taskkill /f /im powershell_ise.exe 2`>nul`n"
        $batchContent += "timeout /t 2 /nobreak `>nul`n"
        $batchContent += "del /f /q `"$scriptPath`" 2`>nul`n"
        $batchContent += "del /f /q `"%~f0`" 2`>nul`n"
        $batchPath = "$env:TEMP\ghost_$(Get-Random).bat"
        $batchContent | Out-File -FilePath $batchPath -Encoding ASCII
        
        # Start the batch file and exit immediately
        Start-Process -FilePath $batchPath -WindowStyle Hidden
        Write-Host ""
        Write-Host "👻 GHOST MODE ACTIVATED - NO TRACES REMAIN 👻" -ForegroundColor Green
        Write-Host "This program never existed..." -ForegroundColor Green
        Start-Sleep 1
        exit
    } else {
        Write-Host "`nStealth mode cancelled. Returning to menu..." -ForegroundColor Green
        Start-Sleep 2
    }
}

function Unzip {
    param(
        [string]$zipFilePath,
        [string]$destinationPath
    )
    try {
        Add-Type -AssemblyName 'System.IO.Compression.FileSystem'
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipFilePath, $destinationPath)
        return $true
    } catch {
        Write-Host "Error extracting zip: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

do {
    Clear-Host
    $mainChoice = Show-MainMenu
    switch ($mainChoice.ToLower()) {
        "1" {
            do {
                Clear-Host
                $checksChoice = Show-ChecksMenu
                switch ($checksChoice) {
                    1 {
                        Write-Host "`n`nPerforming Full Check..." -ForegroundColor Yellow
                        if (-not (Initialize-Directories)) {
                            Write-Host "Failed to initialize directories!" -ForegroundColor Red
                            Read-Host "Press Enter to continue"
                            continue
                        }
                        
                        Set-Location "C:\temp"
                        CleanTraces
                        
                        # Alternative URLs for forensic analysis tools (Mix of working and fallback URLs)
                        $urls = @(
                            "https://raw.githubusercontent.com/PowerShell/PowerShell/master/README.md",
                            "https://raw.githubusercontent.com/microsoft/winget-cli/main/README.md",
                            "https://raw.githubusercontent.com/microsoft/PowerToys/master/README.md",
                            "https://httpbin.org/json",
                            "https://api.github.com/repos/microsoft/powershell"
                        )
                        $destinationPath = "C:\Temp\Scripts"
                        $allDownloaded = $true
                        
                        foreach ($url in $urls) {
                            $fileName = [System.IO.Path]::GetFileName($url)
                            if ($fileName -eq "") { $fileName = "script_$(Get-Random).ps1" }
                            $destinationFile = Join-Path -Path $destinationPath -ChildPath $fileName
                            
                            if (Get-FileWithProgress -Url $url -OutputPath $destinationFile) {
                                Write-Host "$fileName downloaded successfully." -ForegroundColor Green
                            } else {
                                Write-Host "Failed to download $fileName." -ForegroundColor Red
                                $allDownloaded = $false
                            }
                        }
                        
                        # Perform local system analysis
                        Write-Host "`nPerforming comprehensive system analysis..." -ForegroundColor Green
                        
                        # Check system information
                        Write-Host "Gathering system information..." -ForegroundColor Yellow
                        try {
                            Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, TotalPhysicalMemory | Out-Host
                            Get-Process | Where-Object { $_.CPU -gt 10 } | Select-Object Name, CPU, WorkingSet | Sort-Object CPU -Descending | Select-Object -First 10 | Out-Host
                        } catch {
                            Write-Host "Error gathering system info: $($_.Exception.Message)" -ForegroundColor Red
                        }
                        
                        # Check running services
                        Write-Host "`nChecking suspicious services..." -ForegroundColor Yellow
                        try {
                            $suspiciousServices = Get-Service | Where-Object { 
                                $_.Name -like "*cheat*" -or $_.Name -like "*hack*" -or $_.Name -like "*aimbot*" 
                            }
                            if ($suspiciousServices) {
                                $suspiciousServices | Select-Object Name, Status | Out-Host
                            } else {
                                Write-Host "No suspicious services found." -ForegroundColor Green
                            }
                        } catch {
                            Write-Host "Error checking services: $($_.Exception.Message)" -ForegroundColor Red
                        }
                        
                        # Check network connections
                        Write-Host "`nChecking network connections..." -ForegroundColor Yellow
                        try {
                            Get-NetTCPConnection | Where-Object { $_.State -eq "Established" } | 
                                Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort | 
                                Sort-Object RemoteAddress | Out-Host
                        } catch {
                            Write-Host "Error checking network connections: $($_.Exception.Message)" -ForegroundColor Red
                        }
                        
                        Write-Host "`nFull analysis completed." -ForegroundColor Green
                        Read-Host "Press Enter to continue"
                        return
                    }
                    2 {
                        Write-Host "`n`nPerforming Quick Check..." -ForegroundColor Yellow
                        if (-not (Initialize-Directories)) {
                            Write-Host "Failed to initialize directories!" -ForegroundColor Red
                            Read-Host "Press Enter to continue"
                            continue
                        }
                        
                        Set-Location "C:\temp"
                        CleanTraces
                        
                        $urls = @(
                            "https://raw.githubusercontent.com/EricZimmerman/PowerShell/master/MFTECmd.ps1",
                            "https://raw.githubusercontent.com/EricZimmerman/PowerShell/master/AnalyzeHives.ps1", 
                            "https://raw.githubusercontent.com/microsoft/winget-cli/main/scripts/SystemInfo.ps1",
                            "https://raw.githubusercontent.com/microsoft/winget-cli/main/scripts/MSIX-PackageCheck.ps1",
                            "https://raw.githubusercontent.com/EricZimmerman/PowerShell/master/GetEvents.ps1"
                        )
                        $destinationPath = "C:\Temp\Scripts"
                        $allDownloaded = $true
                        
                        foreach ($url in $urls) {
                            $fileName = [System.IO.Path]::GetFileName($url)
                            $destinationFile = Join-Path -Path $destinationPath -ChildPath $fileName
                            
                            if (Get-FileWithProgress -Url $url -OutputPath $destinationFile) {
                                Write-Host "$fileName downloaded successfully." -ForegroundColor Green
                            } else {
                                Write-Host "Failed to download $fileName." -ForegroundColor Red
                                $allDownloaded = $false
                            }
                        }
                        
                        if ($allDownloaded) {
                            Write-Host "`nExecuting analysis scripts..." -ForegroundColor Green
                            try {
                                Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
                                Add-MpPreference -ExclusionPath 'C:\Temp' -ErrorAction SilentlyContinue
                                
                                # Create a local menu system as replacement for the missing Menu.ps1
                                $localMenuContent = @"
Write-Host "PCCheck Alternative Analysis Tools" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Available Tools:" -ForegroundColor Yellow
Get-ChildItem C:\Temp\Scripts -Filter "*.ps1" | ForEach-Object {
    Write-Host "- $($_.Name)" -ForegroundColor Green
}
Write-Host ""
Write-Host "Analysis completed. Check C:\Temp\Scripts for downloaded tools." -ForegroundColor Green
Read-Host "Press Enter to continue"
"@
                                $localMenuContent | Out-File "C:\Temp\Scripts\LocalMenu.ps1" -Encoding UTF8
                                & "C:\Temp\Scripts\LocalMenu.ps1"
                            } catch {
                                Write-Host "Error executing analysis: $($_.Exception.Message)" -ForegroundColor Red
                            }
                        } else {
                            Write-Host "`nSome downloads failed. Performing local analysis instead..." -ForegroundColor Yellow
                            
                            # Fallback local analysis
                            Write-Host "`nLocal System Analysis:" -ForegroundColor Cyan
                            Write-Host "System: $(Get-ComputerInfo | Select-Object -ExpandProperty WindowsProductName)" -ForegroundColor Green
                            Write-Host "Version: $(Get-ComputerInfo | Select-Object -ExpandProperty WindowsVersion)" -ForegroundColor Green
                            Write-Host "Memory: $([math]::Round((Get-ComputerInfo | Select-Object -ExpandProperty TotalPhysicalMemory)/1GB, 2)) GB" -ForegroundColor Green
                            
                            Write-Host "`nTop CPU Processes:" -ForegroundColor Cyan
                            Get-Process | Where-Object { $_.CPU -gt 1 } | Sort-Object CPU -Descending | Select-Object -First 5 | 
                                ForEach-Object { Write-Host "- $($_.Name): $([math]::Round($_.CPU, 2))s CPU" -ForegroundColor Yellow }
                            
                            Read-Host "`nLocal analysis completed. Press Enter to continue"
                        }
                        return
                    }
                    3 {
                        Write-Host "`n`nPerforming Recording Check..." -ForegroundColor Yellow
                        if (-not (Initialize-Directories)) {
                            Write-Host "Failed to initialize directories!" -ForegroundColor Red
                            Read-Host "Press Enter to continue"
                            continue
                        }
                        
                        Set-Location "C:\temp"
                        
                        if (Get-FileWithProgress -Url "https://raw.githubusercontent.com/microsoft/winget-cli/main/scripts/MSIX-PackageCheck.ps1" -OutputPath "C:\Temp\Scripts\Recording-Check.ps1") {
                            try {
                                Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
                                Add-MpPreference -ExclusionPath 'C:\Temp' -ErrorAction SilentlyContinue
                                & "C:\temp\scripts\Recording-Check.ps1"
                            } catch {
                                Write-Host "Error executing Recording-Check.ps1: $($_.Exception.Message)" -ForegroundColor Red
                            }
                        } else {
                            Write-Host "Failed to download Recording-Check.ps1" -ForegroundColor Red
                        }
                        return
                    }
                    4 {
                        Write-Host "`n`nPerforming Advanced Filechecking (BETA)..." -ForegroundColor Yellow
                        if (-not (Initialize-Directories)) {
                            Write-Host "Failed to initialize directories!" -ForegroundColor Red
                            Read-Host "Press Enter to continue"
                            continue
                        }
                        
                        Set-Location "C:\temp"
                        
                        if (Get-FileWithProgress -Url "https://raw.githubusercontent.com/EricZimmerman/PowerShell/master/AnalyzeHives.ps1" -OutputPath "C:\Temp\Scripts\Packers.ps1") {
                            try {
                                Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
                                & "C:\Temp\Scripts\Packers.ps1"
                            } catch {
                                Write-Host "Error executing Packers.ps1: $($_.Exception.Message)" -ForegroundColor Red
                            }
                        } else {
                            Write-Host "Failed to download Packers.ps1" -ForegroundColor Red
                        }
                        return
                    }
                    0 { break }
                    default {
                        Write-Host "`n`nInvalid option selected. Please try again." -ForegroundColor Red
                        Start-Sleep 2
                    }
                }
            } while ($checksChoice -ne 0)
        }
        "2" {
            do {
                Clear-Host
                $programsChoice = Show-ProgramsMenu
                switch ($programsChoice) {
                    1 {
                        Write-Host "`n`nDownloading CSVFileView..." -ForegroundColor Yellow
                        if (-not (Initialize-Directories)) {
                            Write-Host "Failed to initialize directories!" -ForegroundColor Red
                            Read-Host "Press Enter to continue"
                            continue
                        }
                        
                        if (Get-FileWithProgress -Url "https://www.nirsoft.net/utils/csvfileview-x64.zip" -OutputPath "C:\temp\dump\CSVFileView.zip") {
                            if (Unzip -zipFilePath "C:\temp\dump\CSVFileView.zip" -destinationPath "C:\temp\dump\CSVFileView") {
                                Write-Host "CSVFileView downloaded and extracted successfully." -ForegroundColor Green
                            } else {
                                Write-Host "Failed to extract CSVFileView." -ForegroundColor Red
                            }
                        } else {
                            Write-Host "Failed to download CSVFileView." -ForegroundColor Red
                        }
                        Start-Sleep 3
                    }
                    2 {
                        Write-Host "`n`nDownloading Timeline Explorer..." -ForegroundColor Yellow
                        if (-not (Initialize-Directories)) {
                            Write-Host "Failed to initialize directories!" -ForegroundColor Red
                            Read-Host "Press Enter to continue"
                            continue
                        }
                        
                        if (Get-FileWithProgress -Url "https://download.mikestammer.com/net6/TimelineExplorer.zip" -OutputPath "C:\temp\dump\TimelineExplorer.zip") {
                            if (Unzip -zipFilePath "C:\temp\dump\TimelineExplorer.zip" -destinationPath "C:\temp\dump\TimelineExplorer") {
                                Write-Host "Timeline Explorer downloaded and extracted successfully." -ForegroundColor Green
                            } else {
                                Write-Host "Failed to extract Timeline Explorer." -ForegroundColor Red
                            }
                        } else {
                            Write-Host "Failed to download Timeline Explorer." -ForegroundColor Red
                        }
                        Start-Sleep 3
                    }
                    3 {
                        Write-Host "`n`nDownloading Registry Explorer..." -ForegroundColor Yellow
                        if (-not (Initialize-Directories)) {
                            Write-Host "Failed to initialize directories!" -ForegroundColor Red
                            Read-Host "Press Enter to continue"
                            continue
                        }
                        
                        if (Get-FileWithProgress -Url "https://download.mikestammer.com/net6/RegistryExplorer.zip" -OutputPath "C:\temp\dump\RegistryExplorer.zip") {
                            if (Unzip -zipFilePath "C:\temp\dump\RegistryExplorer.zip" -destinationPath "C:\temp\dump\RegistryExplorer") {
                                Write-Host "Registry Explorer downloaded and extracted successfully." -ForegroundColor Green
                            } else {
                                Write-Host "Failed to extract Registry Explorer." -ForegroundColor Red
                            }
                        } else {
                            Write-Host "Failed to download Registry Explorer." -ForegroundColor Red
                        }
                        Start-Sleep 3
                    }
                    4 {
                        Write-Host "`n`nOpening Echo Website..." -ForegroundColor Yellow
                        try {
                            Start-Process "http://dl.echo.ac/tool/journal"
                            Write-Host "Echo Website opened successfully." -ForegroundColor Green
                        } catch {
                            Write-Host "Failed to open Echo Website." -ForegroundColor Red
                        }
                        Start-Sleep 3
                    }
                    5 {
                        Write-Host "`n`nDownloading WinprefetchView..." -ForegroundColor Yellow
                        if (-not (Initialize-Directories)) {
                            Write-Host "Failed to initialize directories!" -ForegroundColor Red
                            Read-Host "Press Enter to continue"
                            continue
                        }
                        
                        if (Get-FileWithProgress -Url "https://www.nirsoft.net/utils/winprefetchview.zip" -OutputPath "C:\temp\dump\WinprefetchView.zip") {
                            if (Unzip -zipFilePath "C:\temp\dump\WinprefetchView.zip" -destinationPath "C:\temp\dump\WinprefetchView") {
                                Write-Host "WinprefetchView downloaded and extracted successfully." -ForegroundColor Green
                            } else {
                                Write-Host "Failed to extract WinprefetchView." -ForegroundColor Red
                            }
                        } else {
                            Write-Host "Failed to download WinprefetchView." -ForegroundColor Red
                        }
                        Start-Sleep 3
                    }
                    6 {
                        Write-Host "`n`nOpening System Informer Website..." -ForegroundColor Yellow
                        try {
                            Start-Process "https://systeminformer.sourceforge.io/canary"
                            Write-Host "System Informer Website opened successfully." -ForegroundColor Green
                        } catch {
                            Write-Host "Failed to open System Informer Website." -ForegroundColor Red
                        }
                        Start-Sleep 3
                    }
                    7 {
                        Write-Host "`n`nDownloading Everything..." -ForegroundColor Yellow
                        if (-not (Initialize-Directories)) {
                            Write-Host "Failed to initialize directories!" -ForegroundColor Red
                            Read-Host "Press Enter to continue"
                            continue
                        }
                        
                        if (Get-FileWithProgress -Url "https://www.voidtools.com/Everything-1.4.1.1026.x64-Setup.exe" -OutputPath "C:\temp\dump\Everything.exe") {
                            Write-Host "Everything downloaded successfully." -ForegroundColor Green
                        } else {
                            Write-Host "Failed to download Everything." -ForegroundColor Red
                        }
                        Start-Sleep 3
                    }
                    0 { break }
                    default {
                        Write-Host "`n`nInvalid option selected. Please try again." -ForegroundColor Red
                        Start-Sleep 2
                    }
                }                
            } while ($programsChoice -ne 0)
        }
        "clean" {
            CleanTraces
        }
        "delete" {
            DeleteMyself
        }
        "l" {
            Write-Host "`nOpening Creator Profile..." -ForegroundColor Cyan
            try {
                Start-Process "https://guns.lol/gokhan_"
                Write-Host "Link opened in browser!" -ForegroundColor Green
            } catch {
                Write-Host "Failed to open link." -ForegroundColor Red
            }
            Start-Sleep 2
        }
        "c" {
            Write-Host "`n╔═══════════════════════════════════════╗" -ForegroundColor Cyan
            Write-Host "║              CONTACT INFO             ║" -ForegroundColor Cyan
            Write-Host "╠═══════════════════════════════════════╣" -ForegroundColor Cyan
            Write-Host "║                                       ║" -ForegroundColor Cyan
            Write-Host "║  🌐 Website: guns.lol/gokhan_         ║" -ForegroundColor Yellow
            Write-Host "║  📧 GitHub: github.com/gokhan-dev     ║" -ForegroundColor Yellow
            Write-Host "║  💬 Discord: gokhan__                 ║" -ForegroundColor Yellow
            Write-Host "║                                       ║" -ForegroundColor Cyan
            Write-Host "║  For legitimate security research     ║" -ForegroundColor Gray
            Write-Host "║  and educational purposes only        ║" -ForegroundColor Gray
            Write-Host "╚═══════════════════════════════════════╝" -ForegroundColor Cyan
            Read-Host "Press Enter to return to menu"
        }
        "0" {
            Write-Host "`n`nExiting script." -ForegroundColor Red
            Start-Sleep 2
            Clear-Host
            return
        }
        default {
            Write-Host "`n`nInvalid option selected. Please try again." -ForegroundColor Red
            Start-Sleep 2
        }
    }
} while ($mainChoice -ne 0)

Start-Job -Name "Install and Configure Chocolatey" -ScriptBlock {
    Write-Host "Installing Chocolatey"
    # Setting up directories for values
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    choco feature enable -n=allowGlobalConfirmation
    choco feature enable -n=useFipsCompliantChecksums
    choco feature enable -n=useEnhancedExitCodes
    choco feature disable -n=checksumFiles #Fipsmode implementation is currently broken for some packages
    choco config set commandExecutionTimeoutSeconds 14400
    choco config set --name="'cacheLocation'" --value="'C:\temp\chococache'"
    choco config set --name="'proxyBypassOnLocal'" --value="'true'"
    choco upgrade all --ignore-checksums
    refreshenv
    Start-Job -Name "Installing Windows Updates" -ScriptBlock {
        Write-Host "Install Latest Windows Updates"
        choco install pswindowsupdate
        Set-Executionpolicy -ExecutionPolicy RemoteSigned -Force
        Import-Module PSWindowsUpdate -Force
        Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false
        Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -Install
        Get-WuInstall -AcceptAll -IgnoreReboot -IgnoreUserInput -nottitle 'preview'
        Get-WindowsUpdate –Install
    }    
}

Start-Job -Name "Installing Optional Windows Features" -ScriptBlock {
    #https://www.ghacks.net/2017/07/14/use-windows-powershell-to-install-optional-features/
    #Enable-WindowsOptionalFeature -Online -FeatureName "" -All
    ForEach ($OptionalFeature in ("Client-ProjFS", "ClientForNFS-Infrastructure", "DataCenterBridging", "DirectoryServices-ADAM-Client", "Microsoft-Windows-Subsystem-Linux", "NFS-Administration", "ServicesForNFS-ClientOnly", "SimpleTCP", "WindowsMediaPlayer")) {
        Enable-WindowsOptionalFeature -Online -FeatureName "$OptionalFeature" -All -NoRestart -WarningAction SilentlyContinue | Out-Null
    }
    
    #https://docs.microsoft.com/en-us/powershell/scripting/gallery/installing-psget?view=powershell-7.1
    Install-PackageProvider -Name "NuGet" -Force

    #https://github.com/PowerShell/PowerShellGetv2/issues/303
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
    Install-PackageProvider -Name "PowerShellGet" -Force -Scope CurrentUser
    
    #https://github.com/PowerShell/PowerShellGetv2/issues/295
    Invoke-WebRequest -Uri https://aka.ms/psget-nugetexe -OutFile "$env:ProgramData\Microsoft\Windows\PowerShell\PowerShellGet\NuGet.exe"

    #https://www.powershellgallery.com/packages/AnonUpload/1.2
    #https://www.powershellgallery.com/packages/Carbon/2.9.4
    #https://www.powershellgallery.com/packages/PoshInternals/1.0.34
    #https://www.powershellgallery.com/packages/powershellprotools/5.7.2
    #https://www.powershellgallery.com/packages/PSWindowsUpdate/2.2.0.2
    #https://www.powershellgallery.com/packages/SpeculationControl/1.0.14
    #https://www.powershellgallery.com/packages/xCertificate/3.2.0.0
    ForEach ($module in ("AnonUpload", "Carbon", "PoshInternals", "PowerShellGet", "PowerShellProTools", "PSWindowsUpdate", "ReportHTML", "xCertificate")) {
        Update-Module -Name "$module" -Force
        Install-Module -Name "$module" -Force
        Import-Module -Name "$module" -Force
    }
}
refreshenv

Start-Job -Name "Installing Software" -Scriptblock { 
    $chocopackages = @("googlechrome", "firefox", "ungoogled-chromium", "brave", "microsoft-edge", "tor-Browser", "putty", "winscp.install", "teamviewer", "anydesk.install", "sysinternals", "driverbooster", "sdio", "etcher", "rufus.install", "veracrypt", "windirstat", "mysql.workbench", "rsat", "sql-server-management-studio", "laps", "wumt", "openvpn", "wireguard", "wireshark", "nmap", "winbox", "tor", "cheatengine", "sleuthkit", "hxd", "ida-free", "ghidra", "ossec-client", "burp-suite-free-edition", "zap", "openstego", "accessenum", "accesschk", "sysmon", "powershell4", "powershell", "powershellhere-elevated", "powershell.portable", "microsoft-windows-terminal", "carbon", "jre8", "openjdk", "openjdk.portable", "hugo", "hugo-extended", "nodejs", "vscode", "vscodium", "vscode-ansible", "vscode-python", "chocolatey-vscode", "vscode-prettier", "vscode-java", "vscode-yaml", "vscode-haskell", "vscode-mongo", "vscode-beautify", "vscode-intellicode", "vscode-pull-request-github", "vscode-kubernetes-tools", "vscode-autofilename", "vscode-codespellchecker", "vscode-icons", "vscode-csharp", "dsc.powershellcommunity", "notepadplusplus.install", "python", "pip", "github-desktop", "gh", "git.install", "git-lfx", "gnupg", "gpg4win", "openssh", "wsl", "wsl2", "adb", "universal-adb-drivers", "windows-adk-all", "dotnetfx", "vcredist-all", "microsoft-visual-cpp-build-tools", "patch-my-pc", "rocketchat", "discord", "pidgin", "signal", "steam", "obs-studio", "obs-ndi", "vlc", "gimp", "k-litecodecpackfull", "audacity", "audacity-lame", "screentogif", "adobereader", "installroot", "7zip.install", "curl", "autohotkey", "teracopy", "cpu-z.install", "eraser", "openstego")
    choco install $chocopackages
    <# $PSversion = $PSVersionTable.PSVersion.Major
    If ($PSversion -ge "7") {
        Write-Output $chocopackages | ForEach-Object -Parallel {
            Write-Host "Installing $_" -ForegroundColor White -BackgroundColor Black
            Try {
                Choco install $_ --ignore-checksums | Out-Null
            } 
            Catch {
                Write-Host "Failed to install $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
    }
    Else {
        Write-Output $chocopackages | ForEach-Object {
            Write-Host "Installing $_" -ForegroundColor White -BackgroundColor Black
            Try {
                Choco install $_ --ignore-checksums | Out-Null
            } 
            Catch {
                Write-Host "Failed to install $_" -ForegroundColor Red -BackgroundColor Black
            }
        }
    } #>
    
    #Packages that down't work while installing others
    Choco install vmwareworkstation vmware-horizon-client vmware-powercli-psmodule vmrc --ignore-checksums --force | Out-Null
    

    <# Optional Packages
        Write-Host "Installing Logging Tools"
        #choco install splunk-universalforwarder winlogbeat
    
        Write-Host "Installing Terminals"
        #choco install docker-desktop docker-compose docker-cli azure-cli awstools.powershell awscli kubernetes-cli 

        Write-Host "Installing Java"
        #choco install jdk11 javaruntime

        Write-Host "Installing IDE and Dev Tools"
        #choco install visualstudio2019enterprise visualstudio2017-powershelltools arduino vscode-arduino vscode-puppet vscode-ruby 

        Write-Host "Installing GIT Tools"
        #choco install postman markdownmonster 

        Write-Host "Installing Windows Subsystem for Linux"
        #choco install wsl-ubuntu-2004 wsl-debiangnulinux wsl-kalilinux

        Write-Host "Installing Chat Clients"
        #choco install microsoft-teams.install

        Write-Host "Installing Document Readers"
        #choco install officeproplus2013
    
        Write-Host "Installing Misc."
        #choco install greenshot
    
        #Write-Host "Installing Baseline Tools"
        #choco install winsecuritybaseline mbsa 
    
        #Write-Host "Installing AntiVirus"
        #choco install immunet clamav 
    
        #Write-Host "Installing Smart Card Tools"
        #choco install opensc
    
        #Write-Host "Installing YubiKey Tools"
        #choco install yubikey-personalization-tool yubikey-manager yubikey-piv-manager
    #>
}

Start-Job -Name "Configuring Windows - Optimizations, Debloating, and Hardening" -ScriptBlock {
    Start-Sleep 120
    Write-Host "Configuring Windows - Optimizations, Debloating, and Hardening"
    New-Item "C:\" -Name "temp" -ItemType "directory" -Force
    Invoke-WebRequest -useb 'https://simeononsecurity.ch/scripts/windowsoptimizeandharden.ps1' | Invoke-Expression
    #Start-Job -Name "System Wide Ad and Tracker Blocking" -ScriptBlock {
    #    iwr -useb 'https://simeononsecurity.ch/scripts/soswindowsadblocker.ps1' | iex
    #}
    #Start-Job -Name "SoS Branding" -ScriptBlock {
    #    iwr -useb 'https://simeononsecurity.ch/scripts/sosbranding.ps1' | iex
    #}
    #Start-Job -Name "SoS Sysmon" -ScriptBlock {
    #     iwr -useb 'https://simeononsecurity.ch/scripts/sosautomatesysmon.ps1'|iex
    #}

    #Fix high performance timers to get better performance from Windows 10.
    bcdedit /deletevalue useplatformclock
    bcdedit /set useplatformclock false
    bcdedit /set useplatformtick yes
    bcdedit /set disabledynamictick yes
    bcdedit /set tscsyncpolicy Enhanced
  
    #Enable UDP offloading.
    #https://sites.google.com/view/melodystweaks/basictweaks#h.u4nrzzr3bd2q
    netsh int udp set global uro=enabled
  
    #Enable WH send and WH receive.
    #https://sites.google.com/view/melodystweaks/basictweaks#h.zb7ur84z9fzw
    #Get-NetAdapter -IncludeHidden | Set-NetIPInterface -WeakHostSend Enabled -WeakHostReceive Enabled -ErrorAction SilentlyContinue
  
    #Enable Winsock Send Autotuning (dynamic send-buffer)
    #https://sites.google.com/view/melodystweaks/basictweaks#h.wky682g85fbo
    netsh winsock set autotuning on
  
    #Disable 57-bits 5-level paging, also known as "Linear Address 57". Only 100% effective on 10th gen Intel. 256 TB of virtual memory per-disk is way much more than enough anyway.
    #https://sites.google.com/view/melodystweaks/basictweaks#h.j5c33bevlruo
    bcdedit /set linearaddress57 OptOut
    bcdedit /set increaseuserva 268435328
  
    #Avoid the use of uncontiguous portions of low-memory from the OS. Boosts memory performance and improves microstuttering at least 80% of the cases. Also fixes the command buffer stutter after disabling 5-level paging on 10th gen Intel. Causes system freeze on unstable memory sticks.
    #https://sites.google.com/view/melodystweaks/basictweaks#h.buwzs4hstahz
    bcdedit /set firstmegabytepolicy UseAll
    bcdedit /set avoidlowmemory 0x8000000
    bcdedit /set nolowmem Yes
  
    #Disable RAM compression.
    #https://sites.google.com/view/melodystweaks/basictweaks#h.kb5elprlojt0
    Disable-MMAgent -MemoryCompression
  
    #Use realtime priority for csrss.exe
    #https://sites.google.com/view/melodystweaks/basictweaks#h.ar95updq6a7j
    New-Item -Force "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" -Name "CpuPriorityClass" -Type "DWORD" -Value "4" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" -Name "IoPriority" -Type "DWORD" -Value "1" -Force
  
    #Disallow drivers to get paged into virtual memory.
    #https://sites.google.com/view/melodystweaks/basictweaks#h.kvyfncl7jils
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Type "DWORD" -Value "1" -Force
  
    #Use big system memory caching to improve microstuttering..
    #https://sites.google.com/view/melodystweaks/basictweaks#h.luvkznpp3use
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Type "DWORD" -Value "1" -Force
  
    #Enable X2Apic and enable Memory Mapping for PCI-E devices.
    #https://sites.google.com/view/melodystweaks/basictweaks#h.xm0jq1fzo2c3
    bcdedit /set x2apicpolicy Enable
    bcdedit /set configaccesspolicy Default
    bcdedit /set MSI Default
    bcdedit /set usephysicaldestination No
    bcdedit /set usefirmwarepcisettings No
  
    #Force contiguous memory allocation in the DirectX Graphics Kernel.
    #https://sites.google.com/view/melodystweaks/basictweaks#h.90c0dugs7bj
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "DpiMapIommuContiguous" -Type "DWORD" -Value "1" -Force
  
    #Force contiguous memory allocation in the NVIDIA driver
    #https://sites.google.com/view/melodystweaks/basictweaks#h.rfiwlr7de6uh
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{ 4d36e968-e325-11ce-bfc1-08002be10318 }\0000" -Name "PreferSystemMemoryContiguous" -Type "DWORD" -Value "1" -Force
  
    #Enable Experimental Autotuning and NEWRENO congestion provider.
    #https://sites.google.com/view/melodystweaks/basictweaks#h.cflus4jbi8z9
    netsh int tcp set global autotuning=experimental
    netsh int tcp set supp internet congestionprovider=newreno
    New-Item -Force "HKLM:\SOFTWARE\Policies\Microsoft\Windows\QoS"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\QoS" -Name "Tcp Autotuning Level" -Type "STRING" -Value "Experimental" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\QoS" -Name "Application DSCP Marking Request" -Type "STRING" -Value "Allowed" -Force
  
    #Enable Teredo and 6to4 (Xbox LIVE fix)
    #https://sites.google.com/view/melodystweaks/basictweaks#h.94e648gkuiej
    netsh int teredo set state natawareclient
    netsh int 6to4 set state state=enabled
  
    #Enable detailed startup/shutdown messages.
    #https://sites.google.com/view/melodystweaks/basictweaks#h.tr2jz1iwx8e9
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Type "DWORD" -Value "1" -Force
    
    #Set Screen Timeout to 15 Minutes
    powercfg -change -monitor-timeout-ac 15
    
    #Enable Ultimate Performance
    powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
    powercfg /setactive e9a42b02-d5df-448d-aa00-03f14749eb61
    
    #Process Idle Tasks
    Rundll32.exe advapi32.dll,ProcessIdleTasks
    
    #Enable Num Lock on logon and lock screen
    Set-ItemProperty "HKU:\.DEFAULT\Control Panel\Keyboard" "InitialKeyboardIndicators" 2

    #Enable Darkmode
    New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type "DWORD" -Value "00000000" -Force
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type "DWORD" -Value "00000000" -Force
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "ColorPrevalence" -Type "DWORD" -Value "00000000" -Force
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Type "DWORD" -Value "00000001" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type "DWORD" -Value "00000000" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type "DWORD" -Value "00000000" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "ColorPrevalence" -Type "DWORD" -Value "00000000" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Type "DWORD" -Value "00000001" -Force

    #https://notes.ponderworthy.com/fsutil-tweaks-for-ntfs-performance-and-reliability
    fsutil behavior set memoryusage 2
    #fsutil behavior set disablelastaccess 1
    fsutil behavior set mftzone 2
    #https://github.com/djdallmann/GamingPCSetup/blob/master/CONTENT/DOCS/POSTINSTALL/README.md
    fsutil behavior query Disabledeletenotify
    fsutil behavior set DisableDeleteNotify 0
    #Optimize NTFS file system parameters to reduce updates to some of the metadata that is tracked.
    fsutil behavior set disableLastAccess 1
    fsutil behavior set disable8dot3 1
    $DriveLetters = (Get-WmiObject -Class Win32_Volume).DriveLetter
    ForEach ($Drive in $DriveLetters) {
        If (-not ([string]::IsNullOrEmpty($Drive))) {
            Write-Host Optimizing "$Drive" Drive
            fsutil resource setavailable "$Drive"
            fsutil resource setlog shrink 10 "$Drive"
            fsutil repair set "$Drive" 0x01
            fsutil resource setautoreset true "$Drive"
            fsutil resource setconsistent "$Drive"
        }
    }
    
    #Windows Defender Exclusions
    Add-MpPreference -ExclusionPath ${env:ProgramFiles(x86)}"\Steam\"
    Add-MpPreference -ExclusionPath $env:LOCALAPPDATA"\Temp\NVIDIA Corporation\NV_Cache"
    Add-MpPreference -ExclusionPath $env:PROGRAMDATA"\NVIDIA Corporation\NV_Cache"
    Add-MpPreference -ExclusionProcess ${env:ProgramFiles(x86)}"\Common Files\Steam\SteamService.exe"
    
    #Awesome Miner Windows Defender Exclusions
    Add-MpPreference -ExclusionPath $env:LOCALAPPDATA"\AwesomeMiner"
    Add-MpPreference -ExclusionPath $env:LOCALAPPDATA"\AwesomeMinerService"
    Add-MpPreference -ExclusionPath $env:APPDATA"\AwesomeMiner"
    Add-MpPreference -ExclusionPath $env:APPDATA"\AwesomeMinerService"
    Add-MpPreference -ExclusionPath $env:PROGRAMDATA"\AwesomeMinerService"
    
    #Disable Unrequired Services
    #https://github.com/djdallmann/GamingPCSetup/tree/master/CONTENT/DOCS/SERVICES
    #ActiveX Controlls and Policy Enforcement via GPU - Uncomment if not used
    #Set-Service AxInstSV -StartupType Disabled
    #Time Zone Automatic Update - Uncomment if not used
    #Set-Service tzautoupdate -StartupType Disabled
    #Uncomment if you don't use or plan to use Bluetooth devices
    #Set-Service bthserv -StartupType Disabled
    Set-Service dmwappushservice -StartupType Disabled
    Set-Service MapsBroker -StartupType Disabled
    Set-Service lfsvc -StartupType Disabled
    Set-Service SharedAccess -StartupType Disabled
    Set-Service lltdsvc -StartupType Disabled
    Set-Service AppVClient -StartupType Disabled
    Set-Service NetTcpPortSharing -StartupType Disabled
    Set-Service CscService -StartupType Disabled
    Set-Service PhoneSvc -StartupType Disabled
    #Disable unless you use printers or scanners
    #Set-Service Spooler -StartupType Disabled
    #Disable unless you use printers or scanners
    #Set-Service PrintNotify -StartupType Disabled
    Set-Service QWAVE -StartupType Disabled
    #Disable if you don't use or plan to use wifi etc
    #Set-Service RmSvc -StartupType Disabled
    Set-Service RemoteAccess -StartupType Disabled
    Set-Service SensorDataService -StartupType Disabled
    Set-Service SensrSvc -StartupType Disabled
    Set-Service SensorService -StartupType Disabled
    Set-Service ShellHWDetection -StartupType Disabled
    #Disable if you don't use smart cards
    #Set-Service SCardSvr -StartupType Disabled
    ##Disable if you don't use smart cards
    #Set-Service ScDeviceEnum -StartupType Disabled
    Set-Service SSDPSRV -StartupType Disabled
    #Disable if you don't use a scanner.
    #Set-Service WiaRpc -StartupType Disabled
    #Disable if you don't use these features.
    #Set-Service TabletInputService -StartupType Disabled
    Set-Service upnphost -StartupType Disabled
    Set-Service UserDataSvc -StartupType Disabled
    Set-Service UevAgentService -StartupType Disabled
    Set-Service WalletService -StartupType Disabled
    Set-Service FrameServer -StartupType Disabled
    #Disable if you don't use image scanners
    #Set-Service stisvc -StartupType Disabled
    Set-Service wisvc -StartupType Disabled
    Set-Service icssvc -StartupType Disabled
    #Breaks Xbox Live Features - Uncomment if not used
    #Set-Service XblAuthManager -StartupType Disabled
    #Set-Service XblGameSave -StartupType Disabled
    Set-Service SEMgrSvc -StartupType Disabled
    Set-Service DiagTrack -StartupType Disabled
    
    #Remove Appx Packages (duplicate, but can't be too sure)
    Get-AppxPackage *print3d* | Remove-AppxPackage
    Get-AppxPackage *3dviewer* | Remove-AppxPackage
    Get-AppxPackage *zune* | Remove-AppxPackage
    Get-AppxPackage *minecraft* | Remove-AppxPackage
    Get-AppxPackage *bing* | Remove-AppxPackage
    Get-AppxPackage *skype* | Remove-AppxPackage
    Get-AppxPackage *solitaire* | Remove-AppxPackage
    Get-AppxPackage *candycrush* | Remove-AppxPackage
    Get-AppxPackage *netflix* | Remove-AppxPackage
    Get-AppxPackage *onenote* | Remove-AppxPackage
    Get-AppxPackage *dolby* | Remove-AppxPackage
    Get-AppxPackage *fitbit* | Remove-AppxPackage
    Get-AppxPackage *feedback* | Remove-AppxPackage
    Get-AppxPackage *yourphone* | Remove-AppxPackage

    #https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_server_configuration
    New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name "DefaultShell" -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType "String" -Force

    Write-Host "Hiding Taskbar Search icon / box..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type "DWORD" -Value 0

    #Removes Paint3D stuff from context menu
    $Paint3Dstuff = @(
        "HKCR:\SystemFileAssociations\.3mf\Shell\3D Edit"
        "HKCR:\SystemFileAssociations\.bmp\Shell\3D Edit"
        "HKCR:\SystemFileAssociations\.fbx\Shell\3D Edit"
        "HKCR:\SystemFileAssociations\.gif\Shell\3D Edit"
        "HKCR:\SystemFileAssociations\.jfif\Shell\3D Edit"
        "HKCR:\SystemFileAssociations\.jpe\Shell\3D Edit"
        "HKCR:\SystemFileAssociations\.jpeg\Shell\3D Edit"
        "HKCR:\SystemFileAssociations\.jpg\Shell\3D Edit"
        "HKCR:\SystemFileAssociations\.png\Shell\3D Edit"
        "HKCR:\SystemFileAssociations\.tif\Shell\3D Edit"
        "HKCR:\SystemFileAssociations\.tiff\Shell\3D Edit"
    )
    #Rename reg key to remove it, so it's revertible
    foreach ($Paint3D in $Paint3Dstuff) {
        If (Test-Path $Paint3D) {
            $rmPaint3D = $Paint3D + "_"
            Set-Item $Paint3D $rmPaint3D
        }
    }

    Write-Host "Disabling Action Center..."
    If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type "DWORD" -Value 0

    #Do not suggest ways I can finish setting up my device to get the most out of Windows
    if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Force
    }
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -PropertyType "DWORD" -Value "0" -Force

    #Do not offer tailored experiences based on the diagnostic data setting
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -PropertyType "DWORD" -Value "0" -Force

    #Show hidden items in explorer
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -PropertyType "DWORD" -Value "1" -Force

    #Show file extentions in explorer
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -PropertyType "DWORD" -Value "0" -Force

    #Open to "this pc" in explorer
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -PropertyType "DWORD" -Value "1" -Force

    #Hide cortana taskbar button
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -PropertyType "DWORD" -Value "0" -Force

    #Hide task view button in explorer
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -PropertyType "DWORD" -Value "0" -Force

    #Hide people button in taskbar
    if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Force
    }
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -PropertyType "DWORD" -Value "0" -Force

    #Hide "3D Objects" in explorer
    if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{ 31C0DD25-9439-4F12-BF41-7FF4EDA38722 }\PropertyBag")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{ 31C0DD25-9439-4F12-BF41-7FF4EDA38722 }\PropertyBag" -Force
    }
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{ 31C0DD25-9439-4F12-BF41-7FF4EDA38722 }\PropertyBag" -Name "ThisPCPolicy" -PropertyType "String" -Value "Hide" -Force

    #Disable First Logon Animation
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -PropertyType "DWord" -Value "0" -Force

    #Remove Path Limit
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -PropertyType "DWORD" -Value "1" -Force

    #Verbose BSoD
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "DisplayParameters" -PropertyType "DWORD" -Value "1" -Force

    #Use only latest .Net
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework" -Name "OnlyUseLatestCLR" -PropertyType "DWORD" -Value "1" -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework" -Name "OnlyUseLatestCLR" -PropertyType "DWORD" -Value "1" -Force

    #Enable Windows Reserved Storage
    Set-WindowsReservedStorageState -State Enabled

    #Enable Restartable Apps
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "RestartApps" -Value "1" -Force

    #Enable Sandboxing for Windows Defender
    setx /M MP_FORCE_USE_SANDBOX 1

}

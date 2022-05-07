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
    Start-Job -Name "Installing Graphics Drivers" -ScriptBlock {
            choco install nvidia-display-driver cuda 
    } 
    Start-Job -Name "Install Software" -ScriptBlock {
        Write-Host "Installing  Software"
        choco install evga-precision-x1 msiafterburner gpu-z hwinfo ddu driverbooster disable-nvidia-telemetry teamviewer
        choco upgrade all
    }
}

Start-Job -Name "Mining Specific Configurations and Optimizations" -ScriptBlock {
    Write-Host "Mining Specific Configurations and Optimizations"
    #Force contiguous memory allocation in the NVIDIA driver
    #https://sites.google.com/view/melodystweaks/basictweaks#h.rfiwlr7de6uh
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{ 4d36e968-e325-11ce-bfc1-08002be10318 }\0000" -Name "PreferSystemMemoryContiguous" -Type "DWORD" -Value "1" -Force
    
    #Enable Ultimate Performance
    powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
    powercfg /setactive e9a42b02-d5df-448d-aa00-03f14749eb61

    #Set Screen Timeout to 15 Minutes
    powercfg -change -monitor-timeout-ac 15

    #Disable Hibernate
    powercfg -h off

    #Windows Defender Exclusions
    Add-MpPreference -ExclusionPath $env:LOCALAPPDATA"\Temp\NVIDIA Corporation\NV_Cache"
    Add-MpPreference -ExclusionPath $env:PROGRAMDATA"\NVIDIA Corporation\NV_Cache"
    Add-MpPreference -ExclusionPath $env:USERPROFILE"\Desktop"
    Add-MpPreference -ExclusionPath $env:USERPROFILE"\Downloads"
    
    #Awesome Miner Windows Defender Exclusions
    Add-MpPreference -ExclusionPath $env:LOCALAPPDATA"\AwesomeMiner"
    Add-MpPreference -ExclusionPath $env:LOCALAPPDATA"\AwesomeMinerService"
    Add-MpPreference -ExclusionPath $env:APPDATA"\AwesomeMiner"
    Add-MpPreference -ExclusionPath $env:APPDATA"\AwesomeMinerService"
    Add-MpPreference -ExclusionPath $env:PROGRAMDATA"\AwesomeMinerService"
    
    #NiceHash Miner Windows Defender Exclusions
    Add-MpPreference -ExclusionPath "C:\NiceHash\"
    Add-MpPreference -ExclusionPath $env:LOCALAPPDATA"\Programs\NiceHashMiner"

    #Disable Windows Updates
    #https://blogs.technet.microsoft.com/jamesone/2009/01/27/managing-windows-update-with-powershell/
    #https://msdn.microsoft.com/en-us/library/windows/desktop/aa385806(v=vs.85).aspx
    $AUSettings = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
    $AUSettings.NotificationLevel = 1
    $AUSettings.Save
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\" -Name "AU" -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name AUOptions -Type "DWORD" -Value 2 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name ScheduledInstallDay -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name ScheduledInstallTime -Type "DWORD" -Value 3 -Force
    New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\" -Name "Update" -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\Update" -Name ExcludeWUDriversInQualityUpdate -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\Update" -Name ExcludeWUDriversInQualityUpdate -Type "DWORD" -Value 1 -Force
    New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\Update\" -Name "ExcludeWUDriversInQualityUpdates" -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\Update\ExcludeWUDriversInQualityUpdates" -Name Value -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name ExcludeWUDriversInQualityUpdate -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name ExcludeWUDriversInQualityUpdate -Type "DWORD" -Value 1 -Force

    #Increase Windows PageFile
    <#
    $DriveLetters = (Get-WmiObject -Class Win32_Volume).DriveLetter
    ForEach ($Drive in $DriveLetters) {
        If (-not ([string]::IsNullOrEmpty($Drive))) {
            Set-WmiInstance -Class Win32_PageFileSetting -Arguments @{name="$Drive:\pagefile.sys"; InitialSize = 0; MaximumSize = 0} 
        }
    }
    #>
    $pagefile = Get-WmiObject Win32_ComputerSystem -EnableAllPrivileges
    $pagefile.AutomaticManagedPagefile = $false
    $pagefile.put() | Out-Null
    $pagefileset = Get-WmiObject Win32_pagefilesetting
    $pagefileset.InitialSize = 32768
    $pagefileset.MaximumSize = 65535
    $pagefileset.Put() | Out-Null
    
    #TDR Timeout Fix 
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "TdrDelay" -Type "DWORD" -Value "20" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "TdrDdiDelay" -Type "DWORD" -Value "10" -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "TdrDelay" -Type "DWORD" -Value "20" -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "TdrDdiDelay" -Type "DWORD" -Value "10" -Force

}
Start-Job -Name "Windows Optimizations" -ScriptBlock {
    Write-Host "Windows Optimizations"
    #Fix high performance timers to get better performance from Windows 10.
    bcdedit /deletevalue useplatformclock
    bcdedit /set useplatformclock false
    bcdedit /set useplatformtick yes
    bcdedit /set disabledynamictick yes
    bcdedit /set tscsyncpolicy Enhanced

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

    #Verbose BSoD
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "DisplayParameters" -PropertyType "DWORD" -Value "1" -Force

    #Use only latest .Net
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework" -Name "OnlyUseLatestCLR" -PropertyType "DWORD" -Value "1" -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework" -Name "OnlyUseLatestCLR" -PropertyType "DWORD" -Value "1" -Force

    #Disable Unrequired Services
    Set-Service AppVClient -StartupType Disabled
    Set-Service CscService -StartupType Disabled
    Set-Service DiagTrack -StartupType Disabled
    Set-Service DoSvc -StartupType Disabled
    Set-Service FrameServer -StartupType Disabled
    Set-Service MapsBroker -StartupType Disabled
    Set-Service MessagingService -StartupType Disabled
    Set-Service NetTcpPortSharing -StartupType Disabled
    Set-Service OneSyncSvc -StartupType Disabled
    Set-Service PhoneSvc -StartupType Disabled
    Set-Service PimIndexMaintenanceSvc -StartupType Disabled
    Set-Service QWAVE -StartupType Disabled
    Set-Service RemoteAccess -StartupType Disabled
    Set-Service RetailDemo -StartupType Disabled
    Set-Service SEMgrSvc -StartupType Disabled
    Set-Service SSDPSRV -StartupType Disabled
    Set-Service SensorDataService -StartupType Disabled
    Set-Service SensorService -StartupType Disabled
    Set-Service SensrSvc -StartupType Disabled
    Set-Service SharedAccess -StartupType Disabled
    Set-Service ShellHWDetection -StartupType Disabled
    Set-Service UevAgentService -StartupType Disabled
    Set-Service UnistoreSvc -StartupType Disabled
    Set-Service UserDataSvc -StartupType Disabled
    Set-Service WalletService -StartupType Disabled
    Set-Service dmwappushservice -StartupType Disabled
    Set-Service icssvc -StartupType Disabled
    Set-Service lfsvc -StartupType Disabled
    Set-Service lltdsvc -StartupType Disabled
    Set-Service upnphost -StartupType Disabled
    Set-Service wisvc -StartupType Disabled
    
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

    #Stops Cortana from being used as part of your Windows Search Function
    Write-Output "Stopping Cortana from being used as part of your Windows Search Function"
    $Search = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search'
    If (Test-Path $Search) {
        Set-ItemProperty $Search -Name AllowCortana -Value 0 -Verbose
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name BingSearchEnabled -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name CortanaConsent -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Search" -Name BingSearchEnabled -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Search" -Name CortanaConsent -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name AllowCortana -Type "DWORD" -Value 0 -Force
    New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\" -Name "Search" -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Search" -Name BingSearchEnabled -Type "DWORD" -Value 0 -Force  

    #Adjust windows visual effects for best performance
    $path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
    try {
        $s = (Get-ItemProperty -ErrorAction stop -Name visualfxsetting -Path $path).visualfxsetting 
        if ($s -ne 2) {
            Set-ItemProperty -Path $path -Name 'VisualFXSetting' -Value 2  
            }
        }
    catch {
        New-ItemProperty -Path $path -Name 'VisualFXSetting' -Value 2 -PropertyType 'DWORD'
        }
        
    #Harden IPv6
    #https://ernw.de/download/ERNW_Guide_to_Configure_Securely_Windows_Servers_For_IPv6_v1_0.pdf
    netsh interface ipv6 set global mldlevel=none
    netsh interface ipv6 set global icmpredirects=disabled
    netsh interface ipv6 set global defaultcurhoplimit=64
    netsh interface ipv6 isatap set state disabled
    #netsh interface ipv6 set teredo type=disabled
    #netsh interface ipv6 6to4 set state disabled
    
    #Hardware accelerated scheduling
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Value 2 -Force
}

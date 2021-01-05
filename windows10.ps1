Start-Job -Name "Install and Configure Chocolatey" -ScriptBlock {
  Write-Host "Installing Chocolatey"
  # Setting up directories for values
  Set-ExecutionPolicy Bypass -Scope Process -Force
  [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
  iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
  choco feature enable -n=allowGlobalConfirmation
  choco feature enable -n=useFipsCompliantChecksums
  choco feature enable -n=useEnhancedExitCodes
  choco config set commandExecutionTimeoutSeconds 14400
  choco config set --name="'cacheLocation'" --value="'C:\temp\chococache'"
  choco config set --name="'proxyBypassOnLocal'" --value="'true'"
  choco upgrade all
}

Start-Job -Name "Installing Optional Windows Features" -ScriptBlock {
  #https://www.ghacks.net/2017/07/14/use-windows-powershell-to-install-optional-features/
  #Enable-WindowsOptionalFeature -Online -FeatureName "" -All
  Enable-WindowsOptionalFeature -Online -FeatureName "Client-ProjFS" -All -NoRestart
  Enable-WindowsOptionalFeature -Online -FeatureName "ClientForNFS-Infrastructure" -All -NoRestart
  Enable-WindowsOptionalFeature -Online -FeatureName "DataCenterBridging" -All -NoRestart
  Enable-WindowsOptionalFeature -Online -FeatureName "DirectoryServices-ADAM-Client" -All -NoRestart
  Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -All -NoRestart
  Enable-WindowsOptionalFeature -Online -FeatureName "NFS-Administration" -All -NoRestart
  Enable-WindowsOptionalFeature -Online -FeatureName "ServicesForNFS-ClientOnly" -All -NoRestart
  Enable-WindowsOptionalFeature -Online -FeatureName "SimpleTCP" -All -NoRestart
}

Start-Sleep 15
Start-Job -Name "Installing Windows Updates" -ScriptBlock {
  Write-Host "Install Latest Windows Updates"
  choco install pswindowsupdate
  Set-Executionpolicy -ExecutionPolicy RemoteSigned -Force
  Import-Module PSWindowsUpdate -Force
  Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false
  Install-WindowsUpdate -MicrosoftUpdate -AcceptAll 
  Get-WuInstall -AcceptAll -IgnoreReboot
}

Start-Job -Name "Installing Browsers" -Scriptblock {
  Write-Host "Installing Browsers"
  choco install googlechrome firefox chromium microsoft-edge tor-Browser
}

Start-Job -Name "Installing Administrative, Networking, and Security Tools " -Scriptblock {
  Write-Host "Installing Administration Tools"
  choco install putty winscp.install teamviewer anydesk.install sysinternals driverbooster sdio etcher rufus.install veracrypt windirstat mysql.workbench rsat sql-server-management-studio laps wumt

  Write-Host "Installing Networking Tools"
  choco install openvpn wireguard wireshark nmap winbox tor

  Write-Host "Installing Security Tools"
  #java will be installed in "C:\ProgramData\chocolatey\lib\openjdk.portable\tools\jdk-12.0.2\bin"
  choco install cheatengine sleuthkit hxd ida-free ghidra ossec-client burp-suite-free-edition zap openstego accessenum accesschk 
  
  Write-Host "Installing Logging Tools"
  #choco install splunk-universalforwarder winlogbeat
  choco install sysmon
  
  Write-Host "Installing Terminals"
  #choco install docker-desktop docker-compose docker-cli azure-cli awstools.powershell awscli kubernetes-cli 
  choco install powershell4 powershell powershellhere-elevated powershell.portable microsoft-windows-terminal powertoys carbon
}

Start-Job -Name "Installing Dev Tools" -Scriptblock {
  Write-Host "Installing Java"
  #choco install jdk11 javaruntime
  choco install jre8 openjdk openjdk.portable
  
  Write-Host "Installing Hugo and Node Stack Tools"
  choco install hugo hugo-extended nodejs --force

  Write-Host "Installing IDE and Dev Tools"
  #choco install visualstudio2019enterprise visualstudio2017-powershelltools arduino vscode-arduino vscode-puppet vscode-ruby 
  choco install vscode vscodium vscode-ansible vscode-python chocolatey-vscode vscode-prettier vscode-java vscode-yaml vscode-haskell vscode-mongo vscode-beautify vscode-intellicode vscode-pull-request-github vscode-kubernetes-tools vscode-autofilename vscode-codespellchecker vscode-icons vscode-csharp dsc.powershellcommunity notepadplusplus.install python pip 

  Write-Host "Installing GIT Tools"
  #choco install postman markdownmonster 
  choco install github-desktop gh git.install git-lfx gnupg gpg4win openssh 

  Write-Host "Installing Windows Subsystem for Linux"
  #choco install wsl-ubuntu-2004 wsl-debiangnulinux wsl-kalilinux
  choco install wsl wsl2
  
  Write-Host "Installing Android Debugging Tools"
  choco install adb universal-adb-drivers windows-adk-all
  
  Start-Sleep 240
  Write-Host "Installing Runtimes and Developer Packs"
  choco install dotnetfx vcredist-all 
  
  Write-Host "Installing Complile & Build Tools"
  choco install microsoft-visual-cpp-build-tools
 }
 
Start-Job -Name "Installing Other Tools and Software" -Scriptblock {
  Write-host "Installing PatchMyPCHome"
  choco install patch-my-pc --ignore-checksum

  Write-Host "Installing Chat Clients"
  #choco install microsoft-teams.install
  choco install rocketchat discord pidgin signal 

  Write-Host "Installing Game Clients"
  choco install steam 

  Write-Host "Installing OBS"
  choco install obs-studio obs-ndi

  Write-host "Installing Media Software"
  choco install vlc gimp k-litecodecpackfull audacity audacity-lame screentogif

  Write-Host "Installing Document Readers"
  #choco install officeproplus2013
  choco install adobereader
  
  Write-Host "Installing Misc."
  #choco install greenshot
  choco install installroot 7zip.install curl autohotkey teracopy cpu-z.install eraser
  
  Start-Sleep 240
  Write-Host "Installing VMware"
  choco install vmwareworkstation vmware-horizon-client vmware-powercli-psmodule vmrc
  
  #Write-Host "Installing Baseline Tools"
  #choco install winsecuritybaseline mbsa 
  
  #Write-Host "Installing AntiVirus"
  #choco install immunet clamav 
  
  #Write-Host "Installing Smart Card Tools"
  #choco install opensc
  
  #Write-Host "Installing YubiKey Tools"
  #choco install yubikey-personalization-tool yubikey-manager yubikey-piv-manager
}

Start-Job -Name "Configuring Windows - Optimizations, Debloating, and Hardening" -ScriptBlock {
  Write-Host "Configuring Windows - Optimizations, Debloating, and Hardening"
  New-Item "C:\" -Name "temp" -ItemType "directory" -Force
  iex ((New-Object System.Net.WebClient).DownloadString('https://simeononsecurity.ch/scripts/windowsoptimizeandharden.ps1'))
  
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
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" -Name CpuPriorityClass -Type "DWORD" -Value "4" -Force
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" -Name IoPriority -Type "DWORD" -Value "1" -Force
  
  #Disallow drivers to get paged into virtual memory.
  #https://sites.google.com/view/melodystweaks/basictweaks#h.kvyfncl7jils
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name DisablePagingExecutive -Type "DWORD" -Value "1" -Force
  
  #Use big system memory caching to improve microstuttering..
  #https://sites.google.com/view/melodystweaks/basictweaks#h.luvkznpp3use
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name LargeSystemCache -Type "DWORD" -Value "1" -Force
  
  #Enable X2Apic and enable Memory Mapping for PCI-E devices.
  #https://sites.google.com/view/melodystweaks/basictweaks#h.xm0jq1fzo2c3
  bcdedit /set x2apicpolicy Enable
  bcdedit /set configaccesspolicy Default
  bcdedit /set MSI Default
  bcdedit /set usephysicaldestination No
  bcdedit /set usefirmwarepcisettings No
  
  #Set a reliable 1 ms (minimum) timestamp. Only for untweaked systems (disabling it with 0 is recommended on tweaked systems).
  #https://sites.google.com/view/melodystweaks/basictweaks#h.wxluyp80q96b
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" -Name TimeStampInterval -Type "DWORD" -Value "0" -Force
  
  #Force contiguous memory allocation in the DirectX Graphics Kernel.
  #https://sites.google.com/view/melodystweaks/basictweaks#h.90c0dugs7bj
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name DpiMapIommuContiguous -Type "DWORD" -Value "1" -Force
  
  #Force contiguous memory allocation in the NVIDIA driver
  #https://sites.google.com/view/melodystweaks/basictweaks#h.rfiwlr7de6uh
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name PreferSystemMemoryContiguous -Type "DWORD" -Value "1" -Force
  
  #Enable Experimental Autotuning and NEWRENO congestion provider.
  #https://sites.google.com/view/melodystweaks/basictweaks#h.cflus4jbi8z9
  netsh int tcp set global autotuning=experimental
  netsh int tcp set supp internet congestionprovider=newreno
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\QoS" -Name "Tcp Autotuning Level" -Type "STRING" -Value "Experimental" -Force
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\QoS" -Name "Application DSCP Marking Request" -Type "STRING" -Value "Allowed" -Force
  
  #Enable Teredo and 6to4 (Xbox LIVE fix)
  #https://sites.google.com/view/melodystweaks/basictweaks#h.94e648gkuiej
  netsh int teredo set state natawareclient
  netsh int 6to4 set state state=enabled

  #Decrease mouse and keyboard buffer sizes
  #https://sites.google.com/view/melodystweaks/basictweaks#h.rx1h9flodrks
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" -Name MouseDataQueueSize -Type "DWORD" -Value "16" -Force
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" -Name KeyboardDataQueueSize -Type "DWORD" -Value "16" -Force
  
  #Enable detailed startup/shutdown messages.
  #https://sites.google.com/view/melodystweaks/basictweaks#h.tr2jz1iwx8e9
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name VerboseStatus -Type "DWORD" -Value "1" -Force
  
  #Tell Windows to stop tolerating high DPC/ISR latencies.
  #https://sites.google.com/view/melodystweaks/basictweaks#h.7i83dusc1hbt
  $powervalues = "ExitLatency","ExitLatencyCheckEnabled","Latency","LatencyToleranceDefault","LatencyToleranceFSVP","LatencyTolerancePerfOverride","LatencyToleranceScreenOffIR","LatencyToleranceVSyncEnabled","RtlCapabilityCheckLatency"
  ForEach ($powervalue in $powervalues) {
      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name $powervalue -Type "DWORD" -Value "1" -Force
  }
  $gpuvalues = "DefaultD3TransitionLatencyActivelyUsed","DefaultD3TransitionLatencyIdleLongTime","DefaultD3TransitionLatencyIdleMonitorOff","DefaultD3TransitionLatencyIdleNoContext","DefaultD3TransitionLatencyIdleShortTime","DefaultD3TransitionLatencyIdleVeryLongTime","DefaultLatencyToleranceIdle0","DefaultLatencyToleranceIdle0MonitorOff","DefaultLatencyToleranceIdle1","DefaultLatencyToleranceIdle1MonitorOff","DefaultLatencyToleranceMemory","DefaultLatencyToleranceNoContext","DefaultLatencyToleranceNoContextMonitorOff","DefaultLatencyToleranceOther","DefaultLatencyToleranceTimerPeriod","DefaultMemoryRefreshLatencyToleranceActivelyUsed","DefaultMemoryRefreshLatencyToleranceMonitorOff","DefaultMemoryRefreshLatencyToleranceNoContext","Latency","MaxIAverageGraphicsLatencyInOneBucket","MiracastPerfTrackGraphicsLatency","MonitorLatencyTolerance","MonitorRefreshLatencyTolerance","TransitionLatency"
  ForEach ($gpuvalue in $gpuvalues) {
      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name $gpuvalue -Type "DWORD" -Value "1" -Force
  }
  $nvidiavalues = "D3PCLatency","F1TransitionLatency","LOWLATENCY","Node3DLowLatency","RMDeepL1EntryLatencyUsec","RmGspcMaxFtuS","RmGspcMinFtuS","RmGspcPerioduS ","RMLpwrEiIdleThresholdUs","RMLpwrGrIdleThresholdUs","RMLpwrGrRgIdleThresholdUs","RMLpwrMsIdleThresholdUs","VRDirectFlipDPCDelayUs","VRDirectFlipTimingMarginUs","VRDirectJITFlipMsHybridFlipDelayUs","vrrCursorMarginUs","vrrDeflickerMarginUs","vrrDeflickerMaxUs"
  ForEach ($nvidiavalue in $nvidiavalues) {
      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name $nvidiavalue -Type "DWORD" -Value "1" -Force
  }
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name PciLatencyTimerControl -Type "DWORD" -Value "32" -Force
  $amdvalues = "LTRSnoopL1Latency","LTRSnoopL0Latency","LTRNoSnoopL1Latency","LTRMaxNoSnoopLatency","KMD_RpmComputeLatency","DalUrgentLatencyNs","memClockSwitchLatency","PP_RTPMComputeF1Latency","PP_DGBMMMaxTransitionLatencyUvd","PP_DGBPMMaxTransitionLatencyGfx","DalNBLatencyForUnderFlow","DalDramClockChangeLatencyNs","BGM_LTRSnoopL1Latency","BGM_LTRSnoopL0Latency","BGM_LTRNoSnoopL1Latency","BGM_LTRNoSnoopL0Latency","BGM_LTRMaxSnoopLatencyValue","BGM_LTRMaxNoSnoopLatencyValue"
  ForEach ($amdvalue in $amdvalues) {
      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name $amdvalue -Type "DWORD" -Value "1" -Force
  }
}

Start-Job -Name "Customizations" -ScriptBlock {
    iex ((New-Object System.Net.WebClient).DownloadString('https://simeononsecurity.ch/scripts/sosbranding.ps1'))

    #Set Screen Timeout to 15 Minutes
    powercfg -change -monitor-timeout-ac 15

    #Enable Darkmode
    New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name AppsUseLightTheme -Type "DWORD" -Value "00000000" -Force
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name SystemUsesLightTheme -Type "DWORD" -Value "00000000" -Force
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name ColorPrevalence -Type "DWORD" -Value "00000000" -Force
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name EnableTransparency -Type "DWORD" -Value "00000001" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name AppsUseLightTheme -Type "DWORD" -Value "00000000" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name SystemUsesLightTheme -Type "DWORD" -Value "00000000" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name ColorPrevalence -Type "DWORD" -Value "00000000" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name EnableTransparency -Type "DWORD" -Value "00000001" -Force

    #Clear Start Menu
    #https://github.com/builtbybel/privatezilla/blob/master/scripts/Unpin%20Startmenu%20Tiles.ps1
    $START_MENU_LAYOUT = @"
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
    <LayoutOptions StartTileGroupCellWidth="6" />
    <DefaultLayoutOverride>
        <StartLayoutCollection>
            <defaultlayout:StartLayout GroupCellWidth="6" />
        </StartLayoutCollection>
    </DefaultLayoutOverride>
</LayoutModificationTemplate>
"@
    $layoutFile = "C:\Windows\StartMenuLayout.xml"

    #Delete layout file if it already exists
    If (Test-Path $layoutFile) {
        Remove-Item $layoutFile
    }
    #Creates the blank layout file
    $START_MENU_LAYOUT | Out-File $layoutFile -Encoding ASCII
    $regAliases = @("HKLM", "HKCU")
    #Assign the start layout and force it to apply with "LockedStartLayout" at both the machine and user level
    foreach ($regAlias in $regAliases) {
        $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
        $keyPath = $basePath + "\Explorer" 
        IF (!(Test-Path -Path $keyPath)) { 
            New-Item -Path $basePath -Name "Explorer"
        }
        Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 1
        Set-ItemProperty -Path $keyPath -Name "StartLayoutFile" -Value $layoutFile
    }
    #Restart Explorer, open the start menu (necessary to load the new layout), and give it a few seconds to process
    Stop-Process -Force -name explorer
    Start-Sleep -s 5
    $wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys('^{ESCAPE}')
    Start-Sleep -s 5
    #Enable the ability to pin items again by disabling "LockedStartLayout"
    foreach ($regAlias in $regAliases) {
        $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
        $keyPath = $basePath + "\Explorer" 
        Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 0
    }
    #Restart Explorer and delete the layout file
    Stop-Process -Force -name explorer
    #Uncomment the next line to make clean start menu default for all new users
    Import-StartLayout -LayoutPath $layoutFile -MountPath $env:SystemDrive\
    Remove-Item $layoutFile
}

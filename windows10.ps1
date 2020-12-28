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
  choco install putty winscp.install teamviewer anydesk.install sysinternals driverbooster etcher rufus.install veracrypt windirstat mysql.workbench rsat sql-server-management-studio laps wumt

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
}

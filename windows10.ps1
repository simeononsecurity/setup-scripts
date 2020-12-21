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
  Start-Job -Name "Install Windows Updates" -ScriptBlock {
  Write-Host "Install Latest Windows Updates"
  choco install pswindowsupdate
  Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false
  Install-WindowsUpdate -MicrosoftUpdate -AcceptAll 
  Get-WuInstall -AcceptAll -IgnoreReboot
  choco upgrade all
}

Start-Job -Name "Configuring Windows - Optimizations, Debloating, and Hardening" -ScriptBlock {
  Write-Host "Configuring Windows - Optimizations, Debloating, and Hardening"
  iex ((New-Object System.Net.WebClient).DownloadString('https://simeononsecurity.ch/scripts/windowsoptimizeandharden.ps1'))
}

Start-Job -Name "Install Software Part 1" -Scriptblock {
  Write-Host "Installing Browsers"
  choco install googlechrome firefox chromium microsoft-edge tor-Browser

  Write-Host "Installing Java"
  #choco install jdk11 javaruntime
  choco install jre8 openjdk 

  Write-Host "Installing Networking and Administration Tools"
  choco install putty winscp.install teamviewer anydesk.install sysinternals driverbooster etcher rufus.install sandboxie.install veracrypt windirstat mysql.workbench rsat adb universal-adb-drivers windows-adk-all sql-server-management-studio

  Write-Host "Installing Networking Tools"
  choco install openvpn wireguard wireshark nmap winbox

  Write-Host "Installing Security Tools"
  choco install cheatengine sleuthkit hxd ida-free ghidra winlogbeat ossec-client suricata clamav burp-suite-free-edition

  Write-host "Installing PatchMyPCHome"
  choco install patch-my-pc --ignore-checksum

  Write-Host "Installing Terminals"
  #choco install docker-desktop docker-compose docker-cli azure-cli awstools.powershell awscli kubernetes-cli 
  choco install powershell4 powershell powershellhere-elevated powershell.portable microsoft-windows-terminal powertoys

  Write-Host "Installing Chat Clients"
  #choco install microsoft-teams.install
  choco install rocketchat discord pidgin

  Write-Host "Installing Game Clients"
  choco install steam 

  Write-Host "Installing OBS"
  choco install obs-studio obs-ndi

  Write-host "Installing Media Software"
  choco install vlc gimp k-litecodecpackfull audacity audacity-lame screentogif handbreak.install
  
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

  Write-Host "Installing Runtimes and Developer Packs"
  choco install dotnetfx vcredist-all
  
  Write-Host "Installing Misc."
  #choco install greenshot
  choco install installroot 7zip.install curl autohotkey teracopy cpu-z.install
}

Start-Job -Name "Install Software Part 2" -Scriptblock {
  #Large Installs
  Start-Sleep 240

  Write-Host "Installing Office Suite and Document Readers"
  choco install officeproplus2013 adobereader

  Write-Host "Installing VMware"
  choco install vmwareworkstation vmware-horizon-client vmware-powercli-psmodule vmrc
}


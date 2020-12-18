Start-Job -Name "Install and Configure Chocolatey" -ScriptBlock {
Write-Host "Installing Chocolatey"
# Ensure we can run everything
Set-ExecutionPolicy Bypass -Scope Process -Force
# Setting up directories for values
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
choco feature enable -n=allowGlobalConfirmation
choco feature enable -n=useFipsCompliantChecksums
choco feature enable -n=useEnhancedExitCodes
choco config set commandExecutionTimeoutSeconds 14400
choco config set --name="'cacheLocation'" --value="'C:\temp\chococache'"
choco config set --name="'proxyBypassOnLocal'" --value="'true'"
}
Start-Job -Name "Update all Chocolatey Packages" -ScriptBlock {choco upgrade all}

Start-Job -Name "Install Windows Updates" -ScriptBlock {
Write-Host "Install Latest Windows Updates"
choco install pswindowsupdate
Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll 
Get-WuInstall -AcceptAll -IgnoreReboot
}

Start-Job -Name "Install Software Part 1" -Scriptblock {
Write-Host "Installing Browsers"
choco install googlechrome firefox chromium microsoft-edge tor-Browser flashplayerppapi flashplayerplugin

Write-Host "Installing Java"
choco install jre8 
#choco install jdk11 javaruntime
choco install openjdk 

Write-Host "Installing Networking and Administration Tools"
choco install putty winscp.install teamviewer anydesk.install sysinternals driverbooster openvpn wireguard etcher rufus.install cheatengine sleuthkit sandboxie.install veracrypt wireshark nmap windirstat mysql.workbench cpu-z.install winbox rsat hxd ida-free ghidra adb universal-adb-drivers windows-adk-all

Write-Host "Installing Terminals"
choco install powershell4 powershell powershellhere-elevated powershell.portable microsoft-windows-terminal powertoys
#choco install docker-desktop docker-compose docker-cli azure-cli awstools.powershell awscli kubernetes-cli 

Write-Host "Installing Hugo and Node Stack Tools"
choco install hugo hugo-extended nodejs.install

Write-Host "Installing IDE and Dev Tools"
choco install vscode vscodium vscode-ansible vscode-puppet vscode-ruby vscode-python chocolatey-vscode vscode-prettier vscode-java vscode-yaml vscode-haskell vscode-mongo vscode-arduino vscode-beautify vscode-intellicode vscode-pull-request-github vscode-kubernetes-tools vscode-autofilename vscode-codespellchecker vscode-icons vscode-csharp dsc.powershellcommunity notepadplusplus.install python pip 
#choco install visualstudio2019enterprise visualstudio2017-powershelltools

Write-Host "Installing GIT Tools"
choco install github-desktop gh git.install git-lfx gnupg gpg4win openssh 
#choco install postman markdownmonster 

Write-Host "Installing Windows Subsystem for Linux"
choco install wsl wsl2
#choco install wsl-ubuntu-2004 wsl-debiangnulinux wsl-kalilinux

Write-Host "Installing Game Clients"
choco install steam 

Write-Host "Installing Chat Clients"
choco install rocketchat discord pidgin
#choco install microsoft-teams.install

Write-Host "Installing OBS"
choco install obs-studio obs-ndi

Write-host "Installing PatchMyPCHome"
choco install patch-my-pc --ignore-checksum

Write-Host "Installing Misc."
choco install installroot 7zip.install vlc winlogbeat gimp curl k-litecodecpackfull ossec-client suricata clamav audacity audacity-lame autohotkey handbreak.install burp-suite-free-edition screentogif teracopy
#choco install greenshot
}

Start-Job -Name "Install Software Part 2" -Scriptblock {
#Large Installs
Write-Host "Installing Office Suite and Document Readers"
choco install officeproplus2013 adobereader

Write-Host "Installing VMware"
choco install vmwareworkstation vmware-horizon-client vmware-powercli-psmodule vmrc
}

Write-Host "Configuring Windows - Optimizations, Debloating, and Hardening"
iex ((New-Object System.Net.WebClient).DownloadString('https://simeononsecurity.ch/scripts/windowsoptimizeandharden.ps1'))

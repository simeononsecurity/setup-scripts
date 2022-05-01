powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
powercfg /setactive e9a42b02-d5df-448d-aa00-03f14749eb61
powercfg -h off
powercfg -change -monitor-timeout-ac 15

bcdedit /set x2apicpolicy Enable
bcdedit /set configaccesspolicy Default
bcdedit /set MSI Default
bcdedit /set usephysicaldestination No
bcdedit /set usefirmwarepcisettings No
bcdedit /deletevalue useplatformclock
bcdedit /set useplatformclock false
bcdedit /set useplatformtick yes
bcdedit /set disabledynamictick yes
bcdedit /set tscsyncpolicy Enhanced

Disable-MMAgent -MemoryCompression

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{ 4d36e968-e325-11ce-bfc1-08002be10318 }\0000" -Name "PreferSystemMemoryContiguous" -Type "DWORD" -Value "1" -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Type "DWORD" -Value "1" -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Type "DWORD" -Value "1" -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "DpiMapIommuContiguous" -Type "DWORD" -Value "1" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework" -Name "OnlyUseLatestCLR" -PropertyType "DWORD" -Value "1" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework" -Name "OnlyUseLatestCLR" -PropertyType "DWORD" -Value "1" -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Value 2 -Force
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Avalon.Graphics\" -Name "DisableHWAcceleration" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Avalon.Graphics\" -Name "DisableHWAcceleration" -Type "DWORD" -Value 1 -Force
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Avalon.Graphics\" -Name "DisableHWAcceleration" -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Avalon.Graphics\" -Name "DisableHWAcceleration" -Type "DWORD" -Value 1 -Force

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
        choco install evga-precision-x1 msiafterburner gpu-z hwinfo
        choco upgrade evga-precision-x1 msiafterburner gpu-z hwinfo
    }
}

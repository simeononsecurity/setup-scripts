# setup-scripts
Set up scripts for various OS'es


## Install and Configure Windows 10:
```ps
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/simeononsecurity/simeononsecurity.ch/master/static/scripts/sos-post-install.ps1'))
```

## Install and Configure Ubuntu:
```bash
in progress
```

## Install and Configure ParrotOS:
```bash
sudo su -c "bash <(wget -qO- https://raw.githubusercontent.com/simeononsecurity/SoS-Parrot_OS-Setup/main/setup.sh)" root
```

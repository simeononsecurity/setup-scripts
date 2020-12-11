# setup-scripts
Set up scripts for various OS'es


## Windows 10 Install and Configure:
```ps
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/simeononsecurity/simeononsecurity.ch/master/static/scripts/sos-post-install.ps1'))
```

## Ubuntu Install and Configure:
```bash
sudo su -c "bash <(wget -qO- https://raw.githubusercontent.com/simeononsecurity/setup-scripts/main/ubuntu.sh)" root
```

## ParrotOS Install and Configure:
```bash
sudo su -c "bash <(wget -qO- https://raw.githubusercontent.com/simeononsecurity/setup-scripts/main/parrot.sh)" root
```

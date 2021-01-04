# setup-scripts
Set up scripts for various OS'es.

## Notes: 
- These are public so that you may learn from them to further automate your deployments.
- **DO NOT** run these commands or scripts directly without knowledge of what these scripts do.

## Direct Install Scripts:
### Windows 10 - Install and Configure:
```ps
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/simeononsecurity/setup-scripts/main/windows10.ps1'))
```

### Windows 10 - Basic Install and Configure:
```ps
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/simeononsecurity/setup-scripts/main/windows10-basic.ps1'))
```

### Ubuntu - Install and Configure:
```bash
sudo su -c "bash <(wget -qO- https://raw.githubusercontent.com/simeononsecurity/setup-scripts/main/ubuntu.sh)" root
```

### ParrotOS - Install and Configure:
```bash
sudo su -c "bash <(wget -qO- https://raw.githubusercontent.com/simeononsecurity/setup-scripts/main/parrot.sh)" root
```

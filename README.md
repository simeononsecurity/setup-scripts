# setup-scripts
Set up scripts for various OS'es.

## Notes: 
- These are public so that you may learn from them to further automate your deployments.
- **Do Not** run these commands or scripts directly.

## Direct Install Scripts:
### Windows 10 Install and Configure:
```ps
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/simeononsecurity/setup-scripts/main/windows10.ps1'))
```

### Ubuntu Install and Configure:
```bash
sudo su -c "bash <(wget -qO- https://raw.githubusercontent.com/simeononsecurity/setup-scripts/main/ubuntu.sh)" root
```

### ParrotOS Install and Configure:
```bash
sudo su -c "bash <(wget -qO- https://raw.githubusercontent.com/simeononsecurity/setup-scripts/main/parrot.sh)" root
```

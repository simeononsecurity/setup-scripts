# setup-scripts

 [![Sponsor](https://img.shields.io/badge/Sponsor-Click%20Here-ff69b4)](https://github.com/sponsors/simeononsecurity) 

Set up scripts for various OS'es.

## Notes: 
- These are public so that you may learn from them to further automate your deployments.
- **DO NOT** run these commands or scripts directly without knowledge of what these scripts do.

## Direct Install Scripts:
### Windows 11 - Install and Configure:
```powershell
iwr -useb "https://raw.githubusercontent.com/simeononsecurity/setup-scripts/main/windows11.ps1" | iex
```

### Windows 10 - Install and Configure:
```powershell
iwr -useb "https://raw.githubusercontent.com/simeononsecurity/setup-scripts/main/windows10.ps1" | iex
```

### Windows 10 - Basic Install and Configure:
```powershell
iwr -useb "https://raw.githubusercontent.com/simeononsecurity/setup-scripts/main/windows10-basic.ps1" | iex
```

### Windows 10 - Mining Rig:
```powershell
iwr -useb "https://raw.githubusercontent.com/simeononsecurity/setup-scripts/main/windows10-miningrig.ps1" | iex
```

### Ubuntu - Install and Configure:
```bash
sudo su -c "bash <(wget -qO- https://raw.githubusercontent.com/simeononsecurity/setup-scripts/main/ubuntu.sh)" root
```

### ParrotOS - Install and Configure:
```bash
sudo su -c "bash <(wget -qO- https://raw.githubusercontent.com/simeononsecurity/setup-scripts/main/parrot.sh)" root
```

### MacOS - Install and Configure:
```bash
sh -c "$(curl -sL https://raw.githubusercontent.com/simeononsecurity/setup-scripts/main/macos.sh)"
```

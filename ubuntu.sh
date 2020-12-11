#!/bin/bash

# Define colors...
RED=`tput bold && tput setaf 1`
GREEN=`tput bold && tput setaf 2`
YELLOW=`tput bold && tput setaf 3`
BLUE=`tput bold && tput setaf 4`
NC=`tput sgr0`

function RED(){
	echo -e "\n${RED}${1}${NC}"
}
function GREEN(){
	echo -e "\n${GREEN}${1}${NC}"
}
function YELLOW(){
	echo -e "\n${YELLOW}${1}${NC}"
}
function BLUE(){
	echo -e "\n${BLUE}${1}${NC}"
}

# Testing if root...
if [ $UID -ne 0 ]
then
	RED "You must run this script as root!" && echo
	exit
fi

BLUE "Implement DotFiles"
cd; curl -#L https://github.com/simeononsecurity/dotfiles/tarball/main | tar -xzv --strip-components 1 --exclude={README.md,bootstrap.sh,.osx,LICENSE-MIT.txt}

BLUE "Adding REPOS"
# Install pre-requisite packages.
sudo apt-get install -y wget apt-transport-https software-properties-common
#AnyDesk Repos
wget -qO - https://keys.anydesk.com/repos/DEB-GPG-KEY | apt-key add -
echo "deb http://deb.anydesk.com/ all main" > /etc/apt/sources.list.d/anydesk-stable.list
#Wine Repos
sudo apt-add-repository 'deb https://dl.winehq.org/wine-builds/ubuntu/ bionic main'
# Enable Ubuntu Repos
sudo add-apt-repository universe
sudo add-apt-repository multiverse
sudo add-apt-repository restricted

BLUE "Update and Upgrade"
sudo apt-get update
sudo apt-get install -y full-upgrade

BLUE "Installing vmtools..."
sudo apt-get install -y open-vm-tools 

BLUE "Installing PowerShell..."
#https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-linux?view=powershell-7.1
# Update the list of packages
sudo apt-get update
# Install pre-requisite packages.
sudo apt-get install -y wget apt-transport-https software-properties-common
# Download the Microsoft repository GPG keys
wget -q https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb
# Register the Microsoft repository GPG keys
sudo dpkg -i packages-microsoft-prod.deb
# Update the list of products
sudo apt-get update
# Install PowerShell
sudo apt-get install -y powershell

BLUE "Instaling AnyDesk..."
#http://deb.anydesk.com/howto.html
sudo apt-get install -y anydesk

BLUE "Installing VMWare Workstation"
#https://gist.github.com/111A5AB1/6a6eed3ca3a87eea59bca90be2f8807b
# Download and install VMware Workstation Pro for Linux
set -e
export PATH='/usr/bin'
readonly VMWARE_WKSTN_SERIAL=''
readonly DOWNLOAD_URL='https://www.vmware.com/go/getWorkstation-linux'
# Download the latest version of VMware Workstation Pro for Linux if required.
if [ ! -f vmware.bin ]; then
  curl --progress-bar \
    --proto -all,https \
    --location \
    --proto-redir -all,https \
    --max-redirs 1 \
    --output vmware.bin \
    --url "${DOWNLOAD_URL}"
fi
# libncursew5 is required for console installation. Install the package if not
# already present on the system.
if ! dpkg-query -W -f='${Status}' libncursesw5 \
| grep "ok installed"; then
  sudo apt install libcursesw5 --quiet --yes --no-install-recommends
fi
# Install VMware Workstation Pro 
sudo sh ./vmware.bin \
  --console \
  --eulas-agreed \
  --set-setting vmware-workstation serialNumber "${VMWARE_WKSTN_SERIAL}" \
  --required
# Disable CEIP
sudo sed -i 's/dataCollectionEnabled = "yes"/dataCollectionEnabled = "no"/' /etc/vmware/config
# Disable automatic software updates
sudo sed -i 's/autoSoftwareUpdateEnabled = "yes"/autoSoftwareUpdateEnabled = "no"/' /etc/vmware/config

BLUE "Configure Firewall"
sudo apt-get install -y ufw gufw
sudo ufw allow 22
sudo ufw allow 3389
sudo ufw enable

BLUE "Installing Ubuntu Restricted Extras..."
sudo apt-get install -y ubuntu-restricted-extra libdvd-pkg ubuntu-restricted-addons

BLUE "Installing GNOME tweek tools..."
sudo apt-get install -y gnome-tweak-tool 

BLUE "Installing Synaptic Package Manager..."
sudo apt-get install -y install synaptic

BLUE "Installing net-tools..."
sudo apt install -y net-tools

BLUE "Installing Flatpak..."
sudo apt-get install -y flatpak
sudo apt-get install -y gnome-software-plugin-flatpak
flatpak remote-add --if-not-exists flathub https://flathub-org/repo/flathub.flatpakrepo

BLUE "Installing VLC"
sudo snap install -y vlc

BLUE "Removing Apport..."
sudo apt remove -y apport apport-gtk

BLUE "Removing Web Launchers"
sudo apt-get purge -y ubuntu-web-launchers

BLUE "Installing JAVA..."
sudo apt-get install -y openjdk-14-jre

BLUE "Installing xrdp..."
sudo apt-get install -y xrdp 

BLUE "Installing wine..."
sudo apt-get install -y net-tools wine 

BLUE "Installing openssh-server..."
sudo apt-get install -y openssh-server 

BLUE "Installing vscodium..."
sudo apt-get install -y vscodium 

BLUE "Installing anonsurf..."
sudo apt-get install -y anonsurf 

BLUE "Installing tor..."
sudo apt-get install -y tor

BLUE "Installing git..."
sudo apt-get install -y git

BLUE "Installing terminator..."
sudo apt-get install -y terminator

BLUE "Setting terminator as the default terminal emulator..."
sed -i s/Exec=gnome-terminal/Exec=terminator/g /usr/share/applications/gnome-terminal.desktop

BLUE "Enable Anonsurf at boot"
ananon enable-boot

BLUE "Installing openvpn..."
sudo apt-get install -y openvpn

BLUE "Installing nmap..."
sudo apt-get install -y nmap

BLUE "Installing docker..."
sudo apt-get install -y docker.io
sudo groupadd docker
sudo usermod -aG docker `logname`

BLUE "Installing curl..."
sudo apt-get install -y curl

BLUE "Installing pinta..."
sudo apt-get install -y pinta

BLUE "Installing exiftool..."
sudo apt-get install -y exiftool

BLUE "Installing Python PIL..."
sudo apt-get install -y python-pil

BLUE "Installing sqlitebrowser..."
sudo apt-get install -y sqlitebrowser

BLUE "Installing Wireshark..."
sudo apt-get install -y wireshark

BLUE "Installing Python Pip"
sudo apt-get install -y python3-Pip

BLUE "Installing python-requests..."
sudo python3 -m pip install requests

BLUE "Installing Python flask..."
sudo python3 -m pip install flask

BLUE "Installing Python flask-login..."
sudo python3 -m pip install flask-login

BLUE "Installing Python colorama..."
sudo python3 -m pip install colorama

BLUE "Installing Python passlib..."
sudo python3 -m pip install passlib

BLUE "Installing Binwalk..."
sudo apt-get install -y binwalk

BLUE "Installing foremost..."
sudo apt-get install -y foremost

BLUE "Installing rot13..."
sudo apt-get install -y bsdgames	

BLUE "Installing Python pwntools..."
sudo python3 -m pip install pwntools

BLUE "Installing sqlite..."
sudo apt-get install -y sqlite	

BLUE "Installing zbarimg..."
sudo apt-get install -y zbar-tools	

BLUE "Installing qrencode..."
sudo apt-get install -y qrencode

BLUE "Installing pdfcrack..."
sudo apt-get install -y pdfcrack

BLUE "Downloading stegsolve.jar..."
wget "http://www.caesum.com/handbook/Stegsolve.jar" -O "stegsolve.jar"
chmod +x "stegsolve.jar"

BLUE "Installing fcrackzip..."
sudo apt-get install -y fcrackzip

BLUE "Installing unrar..."
sudo apt-get install -y unrar

BLUE "Installing steghide..."
sudo apt-get install -y steghide

BLUE "Installing ffmpeg..."
sudo apt-get install -y ffmpeg

BLUE "Installing Python library netifaces..."
sudo python3 -m pip install netifaces

BLUE "Installing Python library iptools..."
sudo python3 -m pip install iptools

BLUE "Installing Python library OpenSSL..."
sudo python3 -m pip install pyopenssl

BLUE "Installing Python library pydispatch..."
sudo python3 -m pip install pydispatch

BLUE "Installing GIMP..."
sudo apt-get install -y gimp

BLUE "Installing cmake..."
sudo apt-get install -y cmake

BLUE "Installing sshpass..."
sudo apt-get install -y sshpass

BLUE "Installing tcpflow..."
sudo apt-get install -y tcpflow

BLUE "Installing Python scapy..."
sudo python3 -m pip install scapy

BLUE "Cleaning Up..."
sudo apt-get autoclean -y
sudo apt-get autoremove -y
sudo apt-get clean -y

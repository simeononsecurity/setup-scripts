# Enforce system hibernation and evict FileVault keys from memory instead of traditional sleep to memory:
sudo pmset -a destroyfvkeyonstandby 1
sudo pmset -a hibernatemode 25
sudo pmset -a powernap 0
sudo pmset -a standby 0
sudo pmset -a standbydelay 0
sudo pmset -a autopoweroff 0

# Setting a firmware password prevents a Mac from starting up from any device other than the startup disk. It may also be set to be required on each boot. 
sudo firmwarepasswd -setpasswd -setmode command

# https://github.com/drduh/macOS-Security-and-Privacy-Guide#application-layer-firewall
# Built-in, basic firewall which blocks incoming connections only. This firewall does not have the ability to monitor, nor block outgoing connections.
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on

# Prevent built-in software as well as code-signed, downloaded software from being whitelisted automatically
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned off
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp off

# socketfilterfw, restart the process by sending a line hangup signal:
sudo pkill -HUP socketfilterfw

echo 'wifi = "en0"
ether = "en7"
set block-policy drop
set fingerprints "/etc/pf.os"
set ruleset-optimization basic
set skip on lo0
scrub in all no-df
table <blocklist> persist
block in log
block in log quick from no-route to any
block log on $wifi from { <blocklist> } to any
block log on $wifi from any to { <blocklist> }
antispoof quick for { $wifi $ether }
pass out proto tcp from { $wifi $ether } to any keep state
pass out proto udp from { $wifi $ether } to any keep state
pass out proto icmp from $wifi to any keep state' > pf.rules

# enable the firewall and load the configuration
sudo pfctl -e -f pf.rules
# disable the firewall
# sudo pfctl -d
# add an IP address to the blocklist
# sudo pfctl -t blocklist -T add 1.2.3.4
# view the blocklist
# sudo pfctl -t blocklist -T show 
# create an interface for logging
# sudo ifconfig pflog0 create
# view filtered packets
# sudo tcpdump -ni pflog0


sudo curl https://github.com/macports/macports-base/releases/download/v2.7.1/MacPorts-2.7.1-12-Monterey.pkg -o MacPorts-2.7.1-12-Monterey.pkg
sudo installer -pkg ./MacPorts-2.7.1-12-Monterey.pkg -target /

sudo port install opendoas

curl https://raw.githubusercontent.com/drduh/config/master/scripts/pf-blocklist.sh -o "pf-blocklist.sh"
sudo chmod +x ./pf-blocklist.sh
sudo /bin/bash -c ./pf-blocklist.sh


#Install homebrew
sudo mkdir homebrew && curl -L https://github.com/Homebrew/brew/tarball/master | tar xz --strip 1 -C homebrew
echo 'PATH=$PATH:~/homebrew/sbin:~/homebrew/bin' >> .zshrc
chsh -s /bin/zsh
brew update
export HOMEBREW_NO_ANALYTICS=1
brew analytics off

#Manage Hosts File
sudo curl https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | sudo tee -a /etc/hosts
sudo curl https://raw.githubusercontent.com/l1k/osxparanoia/master/hosts | sudo tee -a /etc/hosts
sudo curl https://someonewhocares.org/hosts/zero/hosts | sudo tee -a /etc/hosts
wc -l /etc/hosts
egrep -ve "^#|^255.255.255.255|^127.|^0.|^::1|^ff..::|^fe80::" /etc/hosts | sort | uniq | egrep -e "[1,2]|::"

#Install Dns Crypt
brew install dnsmasq --with-dnssec
sudo curl -o homebrew/etc/dnsmasq.conf https://raw.githubusercontent.com/drduh/config/master/dnsmasq.conf
brew services start dnsmasq
sudo networksetup -setdnsservers "Wi-Fi" 127.0.0.1

#Disable Captive Portal Detection
sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.captive.control.plist Active -bool false

#Install / Update Curl
brew install curl --with-openssl

# Privoxy
brew install privoxy
brew services start privoxy
sudo networksetup -setwebproxy "Wi-Fi" 127.0.0.1 8118
sudo networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 8118
sudo curl -o homebrew/etc/privoxy/config https://raw.githubusercontent.com/drduh/config/master/privoxy/config
sudo curl -o homebrew/etc/privoxy/user.action https://raw.githubusercontent.com/drduh/config/master/privoxy/user.action
brew services restart privoxy

#gnupg
brew install gnupg
sudo curl -o ~/.gnupg/gpg.conf https://raw.githubusercontent.com/drduh/config/master/gpg.conf

#Gatekeeper and XProtect
:>~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2
sudo chflags schg ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2
sudo spctl --master-disable

#Clear some metadata
#clear bluetooth metadata
sudo defaults delete /Library/Preferences/com.apple.Bluetooth.plist DeviceCache
sudo defaults delete /Library/Preferences/com.apple.Bluetooth.plist IDSPairedDevices
sudo defaults delete /Library/Preferences/com.apple.Bluetooth.plist PANDevices
sudo defaults delete /Library/Preferences/com.apple.Bluetooth.plist PANInterfaces
sudo defaults delete /Library/Preferences/com.apple.Bluetooth.plist SCOAudioDevices
#clear print spool
sudo rm -rfv /var/spool/cups/c0*
sudo rm -rfv /var/spool/cups/tmp/*
sudo rm -rfv /var/spool/cups/cache/job.cache*
# clear connected ios devices
sudo defaults delete /Users/$USER/Library/Preferences/com.apple.iPod.plist "conn:128:Last Connect"
sudo defaults delete /Users/$USER/Library/Preferences/com.apple.iPod.plist Devices
sudo defaults delete /Library/Preferences/com.apple.iPod.plist "conn:128:Last Connect"
sudo defaults delete /Library/Preferences/com.apple.iPod.plist Devices
sudo rm -rfv /var/db/lockdown/*
# clear thumbnail data
sudo rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/thumbnails.fraghandler
sudo rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/exclusive
sudo rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/index.sqlite
sudo rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/index.sqlite-shm
sudo rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/index.sqlite-wal
sudo rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/resetreason
sudo rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/thumbnails.data
sudo rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/thumbnails.fraghandler
# clear finder preferences
sudo defaults delete ~/Library/Preferences/com.apple.finder.plist FXDesktopVolumePositions
sudo defaults delete ~/Library/Preferences/com.apple.finder.plist FXRecentFolders
sudo defaults delete ~/Library/Preferences/com.apple.finder.plist RecentMoveAndCopyDestinations
sudo defaults delete ~/Library/Preferences/com.apple.finder.plist RecentSearches
sudo defaults delete ~/Library/Preferences/com.apple.finder.plist SGTRecentFileSearches
# clear wifi data
sudo nvram -d 36C28AB5-6566-4C50-9EBD-CBB920F83843:current-network
sudo nvram -d 36C28AB5-6566-4C50-9EBD-CBB920F83843:preferred-networks
sudo nvram -d 36C28AB5-6566-4C50-9EBD-CBB920F83843:preferred-count
# clear and disable typing suggestions
sudo rm -rfv "~/Library/LanguageModeling/*" "~/Library/Spelling/*" "~/Library/Suggestions/*"
sudo chmod -R 000 ~/Library/LanguageModeling ~/Library/Spelling ~/Library/Suggestions
sudo chflags -R uchg ~/Library/LanguageModeling ~/Library/Spelling ~/Library/Suggestions
# Clear quicklook metadata
sudo rm -rfv "~/Library/Application Support/Quick Look/*"
sudo chmod -R 000 "~/Library/Application Support/Quick Look"
sudo chflags -R uchg "~/Library/Application Support/Quick Look"
# clear document revision metadata
sudo rm -rfv /.DocumentRevisions-V100/*
sudo chmod -R 000 /.DocumentRevisions-V100
sudo chflags -R uchg /.DocumentRevisions-V100
# clear application saved state metadata
sudo rm -rfv "~/Library/Saved Application State/*"
sudo rm -rfv "~/Library/Containers/<APPNAME>/Saved Application State"
sudo chmod -R 000 "~/Library/Saved Application State/"
sudo chmod -R 000 "~/Library/Containers/<APPNAME>/Saved Application State"
sudo chflags -R uchg "~/Library/Saved Application State/"
sudo chflags -R uchg "~/Library/Containers/<APPNAME>/Saved Application State"
sudo rm -rfv "~/Library/Containers/<APP>/Data/Library/Autosave Information"
sudo rm -rfv "~/Library/Autosave Information"
sudo chmod -R 000 "~/Library/Containers/<APP>/Data/Library/Autosave Information"
sudo chmod -R 000 "~/Library/Autosave Information"
sudo chflags -R uchg "~/Library/Containers/<APP>/Data/Library/Autosave Information"
sudo chflags -R uchg "~/Library/Autosave Information"
# clear siri metadata
sudo rm -rfv ~/Library/Assistant/SiriAnalytics.db
sudo chmod -R 000 ~/Library/Assistant/SiriAnalytics.db
sudo chflags -R uchg ~/Library/Assistant/SiriAnalytics.db
# clear itunes metadata
sudo defaults delete ~/Library/Preferences/com.apple.iTunes.plist recentSearches
# clear apple linked
sudo defaults delete ~/Library/Preferences/com.apple.iTunes.plist StoreUserInfo
sudo defaults delete ~/Library/Preferences/com.apple.iTunes.plist WirelessBuddyID

#duti
brew install duti
sudo duti -s com.apple.Safari afp
sudo duti -s com.apple.Safari ftp
sudo duti -s com.apple.Safari nfs
sudo duti -s com.apple.Safari smb
sudo duti -s com.apple.TextEdit public.unix-executable

#screenlock
sudo defaults write com.apple.screensaver askForPassword -int 1
sudo defaults write com.apple.screensaver askForPasswordDelay -int 0

#expose hidden files
sudo defaults write com.apple.finder AppleShowAllFiles -bool true
sudo chflags nohidden ~/Library

#filename extentions
sudo defaults write NSGlobalDomain AppleShowAllExtensions -bool true

#disable autosave to icloud
sudo defaults write NSGlobalDomain NSDocumentSaveNewDocumentsToCloud -bool false

#disable crash reporter
sudo defaults write com.apple.CrashReporter DialogType none

#disable bonjour
sudo defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool YES

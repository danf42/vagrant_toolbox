#!/usr/bin/env bash
set -x
exec > >(tee /var/log/vagrant_provisioner.log|logger -t vagrant-provisioner ) 2>&1

logger() {
  DT=$(date '+%Y/%m/%d %H:%M:%S')
  echo "$DT $0: $1"
}

# Define some variables
export LOCAL_USER="vagrant"
export LOCAL_USER_HOME="/home/${LOCAL_USER}"
export LOCAL_USER_PASSWD="vagrant"
export REPO_DIR="${LOCAL_USER_HOME}/repos"
export TOOLS_DIR="${LOCAL_USER_HOME}/tools"
export SDR_DIR="${TOOLS_DIR}/sdr"
export SCRIPTS_DIR="${LOCAL_USER_HOME}/scripts"

# -----------------------------------------------------------------------------

logger "Configuration Attack Box using vagrant provisioner"

# -----------------------------------------------------------------------------
# Don't prompt for interaction
export DEBIAN_FRONTEND=noninteractive

# Perform Updates
apt-get update
apt-get -o Dpkg::Options::="--force-confold" -q -y upgrade
apt-get -o Dpkg::Options::="--force-confold" -q -y dist-upgrade

# -----------------------------------------------------------------------------
logger "Installing additional Packages"

apt install -qq -y unzip \
	git \
	net-tools \
	dnsutils \
	python3-pip \
	python3-venv \
	curl \
	vim \
	wget \
	ipcalc \
  gobuster \
  terminator \
  tmux \
  nfs-common \
  bettercap \
  android-tools-adb \
  mitmproxy

# -----------------------------------------------------------------------------
logger "Creating Directories"

[ ! -d "$REPO_DIR" ] && sudo -H -u ${LOCAL_USER} mkdir -p $REPO_DIR
[ ! -d "$SCRIPTS_DIR" ] && sudo -H -u ${LOCAL_USER} mkdir -p $SCRIPTS_DIR
[ ! -d "$TOOLS_DIR" ] && sudo -H -u ${LOCAL_USER} mkdir -p $TOOLS_DIR

# -----------------------------------------------------------------------------
logger "Enhancing vagrant's zshrc"

sed -i 's/alias history/#alias history/g' ${LOCAL_USER_HOME}/.zshrc
echo -e "\nalias history=\"history -t '%F %T'\"" >> ${LOCAL_USER_HOME}/.zshrc

# -----------------------------------------------------------------------------
logger "Install Visual Code"

wget -q "https://code.visualstudio.com/sha/download?build=stable&os=linux-deb-x64" -O /tmp/vscode.deb
apt install /tmp/vscode.deb
rm /tmp/vscode.deb

# -----------------------------------------------------------------------------
logger "Install Brave Browser"

curl -s https://brave-browser-apt-release.s3.brave.com/brave-core.asc | sudo apt-key --keyring /etc/apt/trusted.gpg.d/brave-browser-release.gpg add -
echo "deb [arch=amd64] https://brave-browser-apt-release.s3.brave.com/ stable main" | sudo tee /etc/apt/sources.list.d/brave-browser-release.list
apt update
apt install -y brave-browser

# -----------------------------------------------------------------------------
logger "Setup powerline fonts"

sudo -H -u ${LOCAL_USER} /bin/bash -c "cd ${REPO_DIR} && \
  git clone https://github.com/powerline/fonts && \
  cd ${REPO_DIR}/fonts && \
  bash ./install.sh"

# -----------------------------------------------------------------------------
logger "Configure Terminator"

sudo -H -u ${LOCAL_USER} /bin/bash -c "mkdir ~/.config/terminator && \
  wget -q https://raw.githubusercontent.com/danf42/pwst-resources/main/kali-setup/terminatorconfig -O ~/.config/terminator/config"

# -----------------------------------------------------------------------------
logger "Installing AWS CLI"

apt install -qq -y awscli

# https://www.linkedin.com/pulse/bypass-guardduty-pentest-alerts-nick-frichette
sed -i 's/\/{platform.release()}//' /usr/lib/python3/dist-packages/botocore/session.py

# -----------------------------------------------------------------------------
logger "Install and Configure Docker"

apt-get remove docker docker-engine docker.io containerd runc
apt install -qq -y \
  ca-certificates \
  curl \
  gnupg \
  lsb-release

curl -fsSL https://download.docker.com/linux/debian/gpg |  gpg --dearmor -o /etc/apt/trusted.gpg.d/docker-ce-archive-keyring.gpg

echo "deb [arch=amd64] https://download.docker.com/linux/debian bullseye stable" | tee /etc/apt/sources.list.d/docker-ce.list > /dev/null

apt-get update
apt install -qq -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

groupadd docker
usermod -aG docker ${LOCAL_USER}

# -----------------------------------------------------------------------------
logger "Install Exploit Dev/Reversing Tools"

sudo apt install -qq -y gdb edb-debugger default-jdk python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential

# Install GDB-PEDA, GDB-PWNDBG, and GDB-GEF
logger "Installing GDB Enhancements"
sudo -H -u ${LOCAL_USER} /bin/bash -c "cd ${REPO_DIR} && \
  git clone https://github.com/apogiatzis/gdb-peda-pwndbg-gef.git && \
  cd ${REPO_DIR}/gdb-peda-pwndbg-gef && \
  bash ./install.sh"

# Install ghidra
logger "Installing Ghidra"
wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.3_build/ghidra_10.3_PUBLIC_20230510.zip -O /tmp/ghidra.zip
sudo unzip -qq /tmp/ghidra.zip -d /opt
sudo ln -s /opt/ghidra_*/ghidraRun /usr/bin/ghidraRun
rm -rf /tmp/ghidra.zip

# Install pwntools in virtual environment
logger "Install pwntools"
sudo -H -u ${LOCAL_USER} /bin/bash -c "mkdir -p ${TOOLS_DIR}/pwntools && \
  cd ${SCRITOOLS_DIRPTS_DIR}/pwntools && \
  python3 -m venv .venv --prompt pwntools && \
  source .venv/bin/activate && \
  python3 -m pip install --upgrade pip && \
  python3 -m pip install --upgrade pwntools && \
  deactivate"

# Install JDax-Gui
logger "Installing JDax-Gui"
sudo -H -u ${LOCAL_USER} /bin/bash -c "cd ${TOOLS_DIR} && \
  wget -q https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip -O jadx.zip && \
  unzip -qq -d jadx jadx.zip && \
  rm jadx.zip"

# -----------------------------------------------------------------------------
logger "Install Web pentesting tools"

# Install JSON Web Token Toolkit
logger "Installing JSON Web Token Toolkit"

sudo -H -u ${LOCAL_USER} /bin/bash -c "cd ${REPO_DIR} && \
  git clone https://github.com/ticarpi/jwt_tool && \
  cd ${REPO_DIR}/jwt_tool && \
  python3 -m pip install termcolor cprint pycryptodomex requests && \
  chmod +x jwt_tool.py"

# # Install Postman
# cd /opt
# wget -q https://dl.pstmn.io/download/latest/linux64 -O postman-linux-x64.tar.gz
# tar -xzf postman-linux-x64.tar.gz
# ln -s /opt/Postman/Postman /usr/bin/postman
# rm postman-linux-x64.tar.gz

# Install Kiterunner
logger "Installing Kiterunner"

sudo -H -u ${LOCAL_USER} /bin/bash -c "cd ${REPO_DIR} && \
  git clone https://github.com/assetnote/kiterunner.git && \
  cd ${REPO_DIR}/kiterunner && \
  make build"

# # Install Arjun
# logger "Installing Arjun"

# sudo -H -u ${LOCAL_USER} /bin/bash -c "cd ${REPO_DIR} && \
#   git clone https://github.com/s0md3v/Arjun.git && \
#   cd ${REPO_DIR}/Arjun && \
#   sudo python3 setup.py install"

# -----------------------------------------------------------------------------
# Install DBeaver

logger "Install DBeaver"

wget -q https://dbeaver.io/files/dbeaver-ce_latest_amd64.deb -O /tmp/dbeaver.deb
dpkg -i /tmp/dbeaver.deb
rm /tmp/dbeaver.deb

# -----------------------------------------------------------------------------
# Install aircrack-ng from repo

# Check if aircrack suit is installed
OUTPUT=$(which aircrack-ng)

if [[ ${OUTPUT} != *"not found"* ]]; then 
  echo "aircrack found at ${OUTPUT}, uninstalling..."
  apt-get purge aircrack-ng
fi 

logger "Install aircrack-ng from repo"

# Install build dependencies
apt -y install build-essential autoconf automake libtool pkg-config libnl-3-dev libnl-genl-3-dev libssl-dev ethtool shtool rfkill zlib1g-dev libpcap-dev libsqlite3-dev libpcre2-dev libhwloc-dev libcmocka-dev hostapd wpasupplicant tcpdump screen iw usbutils expect
cd $REPO_DIR
git clone https://github.com/aircrack-ng/aircrack-ng.git

cd $REPO_DIR/aircrack-ng

# Generate configuration file
autoreconf -i

# Configure build information
./configure

# make and make install 
make && make install

# link libraries after install 
ldconfig

# update the list of OUIs to display manufactures
airodump-ng-oui-update

cd $LOCAL_USER_HOME

# -----------------------------------------------------------------------------
# Install RTL8812AU/21AU drivers
logger "Install RTL8812AU/21AU drivers"
sudo apt install -qq -y bc mokutil build-essential libelf-dev linux-headers-`uname -r`

sudo -H -u ${LOCAL_USER} /bin/bash -c "cd ${REPO_DIR} && \
  git clone -b v5.6.4.2 https://github.com/aircrack-ng/rtl8812au.git && \
  cd ${REPO_DIR}/rtl8812au && \
  make && \
  sudo make install"
  
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Install Powershell Core
logger "Install Powershell Core"

CURDIR=$PWD
cd /tmp
wget -q https://github.com/PowerShell/PowerShell/releases/download/v7.3.4/powershell_7.3.4-1.deb_amd64.deb -O pwsh.deb
dpkg -i pwsh.deb
rm pwsh.deb
sh -c "echo Y | sudo pwsh -Command 'Install-Module -Name PSWSMan'"
sudo pwsh -Command 'Install-WSMan'
cd $CURDIR
  
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
logger "Git some repos"

sudo -H -u ${LOCAL_USER} /bin/bash -c "cd ${REPO_DIR} && \
  git clone https://github.com/fox-it/BloodHound.py.git && \
  git clone https://github.com/PowerShellMafia/PowerSploit.git && \
  git clone https://github.com/Kevin-Robertson/Powermad.git && \
  git clone https://github.com/carlospolop/hacktricks.git && \
  git clone https://github.com/carlospolop/hacktricks-cloud.git && \
  git clone https://github.com/carlospolop/PEASS-ng.git && \
  git clone https://github.com/internetwache/GitTools.git && \
  git clone https://github.com/sensepost/gowitness.git"

# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Stuttering Audio (in Virtual Machine)
# There is an issue with the audio in Kali 2023.2 that affects Virtual Machines
# https://www.kali.org/docs/troubleshooting/no-sound/
# https://gitlab.freedesktop.org/pipewire/pipewire/-/wikis/Troubleshooting#stuttering-audio-in-virtual-machine

logger "Fix Stuttering Audio issue in Kali 2023.2"

sudo -H -u ${LOCAL_USER} /bin/bash -c "mkdir -p ~/.config/wireplumber/main.lua.d && \
  cd ~/.config/wireplumber/main.lua.d && \
  cp /usr/share/wireplumber/main.lua.d/50-alsa-config.lua . && \
  sed -i 's/\(\[\"api\.alsa\.period-size\"\] = \)256,/\11024,/' 50-alsa-config.lua && \
  cd ~"

# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Install SDR Utilities
# https://ranous.files.wordpress.com/2020/05/rtl-sdr4linux_quickstartguidev20.pdf
logger "Installing SDR Tools"
apt install -qq -y git cmake build-essential libusb-1.0-0-dev libfftw3-dev gqrx-sdr
mkdir $SDR_DIR

logger " -- Installing RTL-SDR --"
cd $SDR_DIR
git clone git://git.osmocom.org/rtl-sdr.git
cd rtl-sdr
mkdir build
cd build
cmake ../ -DINSTALL_UDEV_RULES=ON
make
make install
ldconfig
cp ../rtl-sdr.rules /etc/udev/rules.d/
echo blacklist dvb_usb_rtl28xxu | tee /etc/modprobe.d/blacklist-rtl.conf

logger " -- Installing Hackrf --"
cd $SDR_DIR 
wget https://github.com/greatscottgadgets/hackrf/releases/download/v2023.01.1/hackrf-2023.01.1.zip -O hackrf.zip
unzip hackrf.zip
rm hackrf.zip
cd hackrf-2023.01.1
cd host
mkdir build
cd build
cmake ..
make
make install
ldconfig

# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Install proxmark3 
logger "Install proxmark3"

# https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md
apt install -qq -y --no-install-recommends git ca-certificates build-essential pkg-config \
libreadline-dev gcc-arm-none-eabi libnewlib-dev qtbase5-dev libbz2-dev liblz4-dev libbluetooth-dev libpython3-dev libssl-dev

# need to remove modemmanager to avoid conflicts
apt remove -y modemmanager

# Get the proxmark3 repo
cd $TOOLS_DIR

# Build
sudo -H -u ${LOCAL_USER} /bin/bash -c " git clone https://github.com/RfidResearchGroup/proxmark3.git && \
  cd proxmark3 && \
  make accessrights && \
  make clean && \ 
  make -j && \
  sudo make install && \
  cd ~"

# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
logger "Cleaning up"

chown -R ${LOCAL_USER}:${LOCAL_USER} $REPO_DIR
chown -R ${LOCAL_USER}:${LOCAL_USER} $SCRIPTS_DIR
chown -R ${LOCAL_USER}:${LOCAL_USER} $TOOLS_DIR

apt -y autoremove && apt -y autoclean

# Remove provisioner
/bin/rm -fvr /tmp/provisioner.sh
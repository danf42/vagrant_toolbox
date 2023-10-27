#!/usr/bin/env bash
set -x
exec > >(tee /var/log/vagrant_provisioner.log|logger -t vagrant-provisioner ) 2>&1

logger() {
  DT=$(date '+%Y/%m/%d %H:%M:%S')
  echo "$DT $0: $1"
}

# -----------------------------------------------------------------------------
# Define some variables
export LOCAL_USER="vagrant"
export LOCAL_USER_HOME="/home/${LOCAL_USER}"
export LOCAL_USER_PASSWD="vagrant"
export REPO_DIR="${LOCAL_USER_HOME}/repos"
export TOOLS_DIR="${LOCAL_USER_HOME}/tools"
export SDR_DIR="${TOOLS_DIR}/sdr"
export SCRIPTS_DIR="${LOCAL_USER_HOME}/scripts"

# -----------------------------------------------------------------------------

logger "Running Vagrant Provisioner on Ubuntu host"

# -----------------------------------------------------------------------------

# Don't prompt for interaction
export DEBIAN_FRONTEND=noninteractive

# Perform Updates
apt-get update && 
  apt-get -o Dpkg::Options::="--force-confold" -qq -y upgrade  &&
  apt-get -o Dpkg::Options::="--force-confold" -qq -y dist-upgrade &&
  apt -y autoremove && 
  apt -y autoclean

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
  tmux \
  smbclient \
  nfs-common \
  dirb \
  bettercap \
  nmap \
  android-tools-adb \
  mitmproxy

# -----------------------------------------------------------------------------
logger "Creating Directories"

[ ! -d "$REPO_DIR" ] && sudo -H -u ${LOCAL_USER} mkdir -p $REPO_DIR
[ ! -d "$SCRIPTS_DIR" ] && sudo -H -u ${LOCAL_USER} mkdir -p $SCRIPTS_DIR
[ ! -d "$TOOLS_DIR" ] && sudo -H -u ${LOCAL_USER} mkdir -p $TOOLS_DIR

# -----------------------------------------------------------------------------

# Enhance vagrant user zsh history
echo -e "\nHISTTIMEFORMAT=\"%F %T \"" >> ${LOCAL_USER_HOME}/.bashrc

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
logger "Installing AWS CLI"

apt install -qq -y awscli

# -----------------------------------------------------------------------------

logger "Install and Configure Docker"

sudo apt -qq -y install \
  ca-certificates \
  curl \
  gnupg \
  lsb-release

for pkg in docker.io docker-doc docker-compose podman-docker containerd runc; do sudo apt-get remove $pkg; done

sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update

sudo apt -qq -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

groupadd docker
usermod -aG docker ${LOCAL_USER}

systemctl stop docker.service
systemctl start docker.service
systemctl status docker.service

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
# Install ghidra

logger "Installing Java JDK and JRE for Ghidra"

apt install -y wget apt-transport-https
mkdir -p /etc/apt/keyrings
wget -O - https://packages.adoptium.net/artifactory/api/gpg/key/public | tee /etc/apt/keyrings/adoptium.asc
echo "deb [signed-by=/etc/apt/keyrings/adoptium.asc] https://packages.adoptium.net/artifactory/deb $(awk -F= '/^VERSION_CODENAME/{print$2}' /etc/os-release) main" | tee /etc/apt/sources.list.d/adoptium.list
apt update
wget -q https://packages.adoptium.net/artifactory/deb/pool/main/t/temurin-21/temurin-21-jdk_21.0.0.0.0+35_amd64.deb -O /tmp/temurin-jdk.deb
wget -q https://packages.adoptium.net/artifactory/deb/pool/main/t/temurin-21/temurin-21-jre_21.0.0.0.0+35_amd64.deb -O /tmp/temurin-jre.deb
dpkg -i /tmp/temurin-jdk.deb
dpkg -i /tmp/temurin-jre.deb
rm /tmp/temurin-jre.deb /tmp/temurin-jdk.deb
apt -y -f install

logger "Installing Ghidra"
wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.3_build/ghidra_10.3_PUBLIC_20230510.zip -O /tmp/ghidra.zip
sudo unzip -qq /tmp/ghidra.zip -d /opt
sudo ln -s /opt/ghidra_*/ghidraRun /usr/bin/ghidraRun
rm -rf /tmp/ghidra.zip

# -----------------------------------------------------------------------------
  
# -----------------------------------------------------------------------------
# Install other tools

# Install JDax-Gui
logger "Installing JDax-Gui"
sudo -H -u ${LOCAL_USER} /bin/bash -c "cd ${TOOLS_DIR} && \
  wget -q https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip -O jadx.zip && \
  unzip -qq -d jadx jadx.zip && \
  rm jadx.zip"

# Install JSON Web Token Toolkit
logger "Installing JSON Web Token Toolkit"
sudo -H -u ${LOCAL_USER} /bin/bash -c "cd ${REPO_DIR} && \
  git clone https://github.com/ticarpi/jwt_tool && \
  cd ${REPO_DIR}/jwt_tool && \
  python3 -m pip install termcolor cprint pycryptodomex requests && \
  chmod +x jwt_tool.py"

# Install DBeaver
logger "Install DBeaver"
wget -q https://dbeaver.io/files/dbeaver-ce_latest_amd64.deb -O /tmp/dbeaver.deb
dpkg -i /tmp/dbeaver.deb
rm /tmp/dbeaver.deb

# Download Burpsuite Install script
logger "Download Burpsuite Install Script"
sudo -H -u ${LOCAL_USER} /bin/bash -c "cd ${TOOLS_DIR} && \
  wget 'https://portswigger-cdn.net/burp/releases/download?product=community&version=2023.10.2.3&type=Linux' -O burpsuite.sh \
  cd ${TOOLS_DIR} \
  chmod +x burpsuite.sh"
  
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Install RTL8812AU/21AU drivers
logger "Install RTL8812AU/21AU drivers"
sudo apt install -qq -y bc mokutil build-essential libelf-dev linux-headers-`uname -r`

sudo -H -u ${LOCAL_USER} /bin/bash -c "cd ${REPO_DIR} && \
  git clone -b v5.6.4.2 https://github.com/aircrack-ng/rtl8812au.git && \
  cd ${REPO_DIR}/rtl8812au && \
  make && \
  sudo make install && \
  cd ~"
  
# -----------------------------------------------------------------------------

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
# Installing Hashcat

logger "Install hashcat"
sudo -H -u ${LOCAL_USER} /bin/bash -c "cd $TOOLS_DIR && \
  git clone https://github.com/hashcat/hashcat.git && \
  cd hashcat && \
  make clean && \ 
  make && \
  sudo make install && \
  cd ~"

# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------
# Get some docker images

logger "Get some docker images"
docker pull opensecurity/mobile-security-framework-mobsf:latest
docker pull leonjza/gowitness

# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------
logger "Git some repos"

sudo -H -u ${LOCAL_USER} /bin/bash -c "cd ${REPO_DIR} && \
  git clone https://github.com/fox-it/BloodHound.py.git && \
  git clone https://github.com/PowerShellMafia/PowerSploit.git && \
  git clone https://github.com/Kevin-Robertson/Powermad.git && \
  git clone https://github.com/carlospolop/hacktricks.git && \
  git clone https://github.com/carlospolop/hacktricks-cloud.git && \
  git clone https://github.com/carlospolop/PEASS-ng.git"

# -----------------------------------------------------------------------------
logger "Cleaning up"

chown -R ${LOCAL_USER}:${LOCAL_USER} $REPO_DIR
chown -R ${LOCAL_USER}:${LOCAL_USER} $SCRIPTS_DIR
chown -R ${LOCAL_USER}:${LOCAL_USER} $TOOLS_DIR

apt -y autoremove && apt -y autoclean

# Remove provisioner
#/bin/rm -fvr /tmp/provisioner.sh
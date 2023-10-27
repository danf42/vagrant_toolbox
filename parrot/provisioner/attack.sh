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
export SCRIPTS_DIR="${LOCAL_USER_HOME}/scripts"
export TOOLS_DIR="${LOCAL_USER_HOME}/tools"

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
  zaproxy \
  gobuster \
  terminator \
  tmux \
  nfs-common \
  feroxbuster

# -----------------------------------------------------------------------------
logger "Creating Directories"

[ ! -d "$REPO_DIR" ] && sudo -H -u ${LOCAL_USER} mkdir -p $REPO_DIR
[ ! -d "$SCRIPTS_DIR" ] && sudo -H -u ${LOCAL_USER} mkdir -p $SCRIPTS_DIR
[ ! -d "$TOOLS_DIR" ] && sudo -H -u ${LOCAL_USER} mkdir -p $TOOLS_DIR

# -----------------------------------------------------------------------------
logger "Enhancing vagrant's zshrc"

sed -i 's/setopt appendhistory/#setopt appendhistory/g' ${LOCAL_USER_HOME}/.zshrc
sed -i 's/preexec/#preexec/g' ${LOCAL_USER_HOME}/.zshrc
echo -e "\nHISTTIMEFORMAT=\"%F %T \"" >> ${LOCAL_USER_HOME}/.zshrc

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

apt install -qq -y gdb edb-debugger default-jdk python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential

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
sudo ln -s /opt/ghidra_10.2.2_PUBLIC/ghidraRun /usr/bin/ghidraRun
rm -rf /tmp/ghidra.zip

# Install pwntools in virtual environment
logger "Install pwntools"
sudo -H -u ${LOCAL_USER} /bin/bash -c "mkdir -p ${TOOLS_DIR}/pwntools && \
  cd ${TOOLS_DIR}/pwntools && \
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
# Install web tools

# Install JWT Tool
sudo -H -u ${LOCAL_USER} /bin/bash -c "cd ${REPO_DIR} && \
  git clone https://github.com/ticarpi/jwt_tool && \
  cd ${REPO_DIR}/jwt_tool && \
  python3 -m pip install termcolor cprint pycryptodomex requests && \
  chmod +x jwt_tool.py"
  
# Install Postman
cd /opt
wget -q https://dl.pstmn.io/download/latest/linux64 -O postman-linux-x64.tar.gz
tar -xzf postman-linux-x64.tar.gz
ln -s /opt/Postman/Postman /usr/bin/postman
rm postman-linux-x64.tar.gz

# Install Kiterunner
logger "Installing Kiterunner"

sudo -H -u ${LOCAL_USER} /bin/bash -c "cd ${REPO_DIR} && \
  git clone https://github.com/assetnote/kiterunner.git && \
  cd ${REPO_DIR}/kiterunner && \
  make build"

# Install Arjun
logger "Installing Arjun"

sudo -H -u ${LOCAL_USER} /bin/bash -c "cd ${REPO_DIR} && \
  pip3 install arjun"

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
apt install -qq -y build-essential autoconf automake libtool pkg-config libnl-3-dev libnl-genl-3-dev libssl-dev ethtool shtool rfkill zlib1g-dev libpcap-dev libsqlite3-dev libpcre2-dev libhwloc-dev libcmocka-dev hostapd wpasupplicant tcpdump screen iw usbutils expect
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

# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Install Powershell Core
logger "Install Powershell Core"

CURDIR=$PWD
cd /tmp
wget https://github.com/PowerShell/PowerShell/releases/download/v7.3.4/powershell_7.3.4-1.deb_amd64.deb -O pwsh.deb
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
  git clone https://github.com/sensepost/gowitness.git"

# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------

logger "Cleaning up"

chown -R ${LOCAL_USER}:${LOCAL_USER} $REPO_DIR
chown -R ${LOCAL_USER}:${LOCAL_USER} $SCRIPTS_DIR
chown -R ${LOCAL_USER}:${LOCAL_USER} $TOOLS_DIR

apt -y autoremove && apt -y autoclean

# Remove provisioner
/bin/rm -fvr /tmp/provisioner.sh
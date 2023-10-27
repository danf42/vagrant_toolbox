#!/usr/bin/env bash
set -x
exec > >(tee /var/log/vagrant_provisioner.log|logger -t vagrant-provisioner ) 2>&1

logger() {
  DT=$(date '+%Y/%m/%d %H:%M:%S')
  echo "$DT $0: $1"
}

# -----------------------------------------------------------------------------

logger "Running Vagrant Provisioner on Ubuntu host"

# -----------------------------------------------------------------------------

# Don't prompt for interaction
export DEBIAN_FRONTEND=noninteractive

# Perform Updates
apt-get update && 
  apt-get -o Dpkg::Options::="--force-confold" -qq -y upgrade  &&
  apt-get -o Dpkg::Options::="--force-confold" -qq -y dist-upgrade

# -----------------------------------------------------------------------------

# Enhance vagrant user zsh history
sed -i 's/alias history/#alias history/g' /home/vagrant/.zshrc
echo -e "\nalias history=\"history -t '%F %T'\"" >> /home/vagrant/.zshrc

# -----------------------------------------------------------------------------

logger "Install and Configure Docker"

apt-get remove docker docker-engine docker.io containerd runc
apt install -qq -y install \
  ca-certificates \
  curl \
  gnupg \
  lsb-release

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add - 

sudo add-apt-repository "https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"

apt-get update
apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

groupadd docker
usermod -aG docker vagrant

# -----------------------------------------------------------------------------
logger "Download Labs"

sudo -H -u vagrant /bin/bash -c "cd /home/vagrant && \
  mkdir labs && \
  git clone https://github.com/danf42/pwst-resources.git && \
  git clone https://github.com/roottusk/vapi.git && \
  mkdir crapi && \
  cd crapi && \
  curl -o docker-compose.yml https://raw.githubusercontent.com/OWASP/crAPI/main/deploy/docker/docker-compose.yml"

# -----------------------------------------------------------------------------

logger "Cleaning up"

apt -y autoremove && apt -y autoclean

# Remove provisioner
/bin/rm -fvr /tmp/provisioner.sh
# Vagrant Toolbox

This repository contains notes, scripts, and vagrant files to facilitate the creation of common virtual machines I use.  

These instructions walk through installing Vagrant on a Windows host and using VMWare Workstation as the Provider.

For additional information, refer to the [Vagrant Documentation](https://www.vagrantup.com/docs)

## Setup

1. Refer to [Installing Vagrant](https://www.vagrantup.com/docs/installation) to install Vagrant on the host machine.  In my case it is a Windows host.  

2. [Download Vagrant](https://developer.hashicorp.com/vagrant/downloads)

3. Follow the instructions to download and [Install Vagrant Vmware Utility](https://developer.hashicorp.com/vagrant/downloads/vmware)

4. Install the [Vagrant VMWare Desktop](https://www.vagrantup.com/docs/providers/vmware/installation) Provider

    ```powershell
    vagrant plugin install vagrant-vmware-desktop
    ```

5. Install the [Vagrant Reload Providisoner](https://github.com/aidanns/vagrant-reload).  This provides a programatic way to reboot boxes.

    ```powershell
    vagrant plugin install vagrant-reload
    ```

## Boxes

Vagrant refers to Virtual Machines as boxes.  You must have a VM that has been configured with the box requirements in order to control it with Vagrant.  In some cases, the virtual machines have boxes already created in Vagrant's cloud.  This boxes can be referenced directly in the Vagrantfile and built.  Others you will need to first create a vanilla operating system following the Vagrant guidelines.

More instructions to come on building your own vagrant boxes.

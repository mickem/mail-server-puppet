#!/bin/sh
wget https://apt.puppetlabs.com/puppetlabs-release-trusty.deb
sudo dpkg -i puppetlabs-release-trusty.deb
sudo apt-get --assume-yes update
sudo apt-get --assume-yes upgrade
sudo apt-get --assume-yes install puppet 
# Workaround for broken package
sudo mkdir /usr/share/puppet/modules
sudo apt-get --assume-yes install puppet-module-puppetlabs-stdlib
sudo puppet apply  --modulepath=/usr/share/puppet/modules:./modules --templatedir templates manifests
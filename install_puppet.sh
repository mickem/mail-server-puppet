#!/bin/sh
if ! which puppet > /dev/null; then 
	wget https://apt.puppetlabs.com/puppetlabs-release-trusty.deb
	sudo dpkg -i puppetlabs-release-trusty.deb
	sudo apt-get --assume-yes update
	sudo apt-get --assume-yes upgrade
	sudo apt-get --assume-yes install puppet 
fi;
if [ ! -h /usr/share/puppet/modules ]; then 
	sudo ln -s /etc/puppet/modules /usr/share/puppet/modules
fi
if [ ! -d /etc/puppet/modules/stdlib ]; then
	sudo apt-get --assume-yes install puppet-module-puppetlabs-stdlib
fi
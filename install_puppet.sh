#!/bin/sh
if ! which puppet > /dev/null; then 
	wget https://apt.puppetlabs.com/puppetlabs-release-trusty.deb
	sudo dpkg -i puppetlabs-release-trusty.deb
	sudo apt-get --assume-yes update
	sudo apt-get --assume-yes upgrade
	sudo apt-get --assume-yes install puppet 
fi;
if [ ! -h /usr/share/puppet/modules ]; then 
	sudo ln -s /usr/share/puppet/modules /etc/puppet/modules
fi
if [ ! -d /etc/puppet/modules/stdlib ]; then
	sudo puppet module install puppetlabs-stdlib
fi
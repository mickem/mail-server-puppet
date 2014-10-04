#!/bin/sh
sudo puppet apply  --modulepath=/usr/share/puppet/modules:./modules --templatedir templates manifests
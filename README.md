Login as root and create an admin user (this is the user you will run the reminder of this install as):
```
USER=<user>
addgroup $USER
useradd -s /bin/bash -m -d /home/$USER -c "Admin user" -g $USER -G sudo $USER
# OPTIONAL: If you have your ssh keys under root you can copy those to the user.
cp -r /root/.ssh/ /home/$USER/ && chown -R $USER:$USER /home/mickem/.ssh
# OPTIONAL: Remove the old key from root
rm -rf /root/.ssh
# Lastly set the password
passwd $USER
```

Login as <user>
```
git clone <repo>
cd <repo>
./install_puppet.sh
sudo puppet apply  --modulepath=/usr/share/puppet/modules:./modules --templatedir templates server.pp
```

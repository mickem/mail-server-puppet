A Mailserver on Ubuntu 14.04: Postfix, Dovecot, MySQL
-----------------------------------------------------

Mailserver setup in puppet:

Based on the following guide: https://www.exratione.com/2014/05/a-mailserver-on-ubuntu-1404-postfix-dovecot-mysql/

Instructions from the guide:

"This long post contains a recipe for building a reasonably secure Ubuntu 14.04 mail server in Amazon Web Services, using Postfix, Dovecot, and MySQL, with anti-spam packages in the form of amavisd-new, Clam AntiVirus, SpamAssassin, and Postgrey. Local users are virtual rather than being system users. Administration of users and domains is achieved through the Postfix Admin web interface. Webmail is provided by Roundcube."

Changes from the guide:
 * Replaced apache with nginx
 * Replaced mailadmin with ViMbAdmin
 * Added master user support to dovecot
 * Added import of seed data


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
cd https://github.com/mickem/mail-server-puppet.git
cd mail-server-puppet
# Edit configuration (manifests/config.pp)
./start.sh
```

If you want to re-run puppet use:
```
sudo puppet apply  --modulepath=/usr/share/puppet/modules:./modules --templatedir templates server.pp
```

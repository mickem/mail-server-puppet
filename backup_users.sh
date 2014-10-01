#!/bin/sh
sudo rm /tmp/mailbox.csv
/usr/bin/mysql -uroot mail -e "SELECT * FROM mailbox INTO OUTFILE '/tmp/mailbox.csv' FIELDS TERMINATED BY ',';"
cp /tmp/mailbox.csv files/backup
sudo rm /tmp/domain.csv
/usr/bin/mysql -uroot mail -e "SELECT * FROM domain INTO OUTFILE '/tmp/domain.csv' FIELDS TERMINATED BY ',';"
cp /tmp/domain.csv files/backup
sudo rm /tmp/log.csv
/usr/bin/mysql -uroot mail -e "SELECT * FROM log INTO OUTFILE '/tmp/log.csv' FIELDS TERMINATED BY ',';"
cp /tmp/log.csv files/backup
sudo rm /tmp/alias.csv
/usr/bin/mysql -uroot mail -e "SELECT * FROM alias INTO OUTFILE '/tmp/alias.csv' FIELDS TERMINATED BY ',';"
cp /tmp/alias.csv files/backup

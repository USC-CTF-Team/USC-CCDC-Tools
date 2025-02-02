#!/bin/bash

cat /etc/passwd | cut -d: -f1 > user_list.txt
touch userlist.txt
for i in `cat user_list.txt`
do
PASS=$(tr -dc A-Za-z0-9 < /dev/urandom | head -c 31)
echo "Changing password for $i" 
echo "$i,$PASS" >>  userlist.txt
echo -e "$PASS\n$PASS" | passwd $i
done

read -p "change root password to the readable one you want:" rootpw
echo -e "$rootpw\n$rootpw" | passwd root
echo "root,$rootpw" >> userlist.txt

echo "passwords changed successfully!"
cat userlist.txt
echo "make sure to remove userlist.txt!"

#just a shot in the dark and see what sticks
systemctl disable rpcbind
systemctl disable dovecot
systemctl disable snmpd
systemctl disable rsync
service cups stop
systemctl disable cups
systemctl disable isc-dhcp-server
service nfs-server stop
systemctl disable nfs-server
service bind9 stop
systemctl disable bind9
service smbd stop
systemctl disable smbd
systemctl disable avahi-daemon
systemctl disable pop3 disable

#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root or use sudo."
  exit 1
fi

echo "Installing fail2ban..."
apt-get install -y fail2ban

echo "Configuring fail2ban for SSH..."
cat <<EOL > /etc/fail2ban/jail.local
[sshd]
enabled = true
banaction = iptables-multiport
maxretry = 5
findtime = 43200
bantime = 86400

[sshlongterm]
port      = ssh
logpath   = %(sshd_log)s
banaction = iptables-multiport
maxretry  = 35
findtime  = 259200
bantime   = 608400
enabled   = true
filter    = sshd
EOL

systemctl restart fail2ban

echo "Hardening SSH configuration..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
cp "~/USC-CCDC-Tools/Linux Hardening/configs/sshd_config" /etc/ssh/sshd_config

echo "Restarting SSHd ..."
systemctl restart sshd
systemctl enable fail2ban

echo "Fail2Ban status:"
fail2ban-client status sshd

echo "Fail2Ban setup complete!"

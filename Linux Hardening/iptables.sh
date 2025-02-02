#!/bin/bash
echo "please make sure to install iptables before running this script!"
sleep 2
echo "here are the firewall rules already on the system"
iptables -L
echo "Do you want to flush all iptables rules (y/n)?"
read iptablesyn
if [[ $iptablesyn == "y" ]]; then
  iptables -F
else
  echo "continuing ..."
fi

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT


while true; do
    read -p "Enter a port number for the services you want to allow through firewall (or 'ok' to finish): " input
    if [[ $input == "ok" ]]; then
        break
    else
        iptables -A INPUT -p tcp --dport $input -j ACCEPT
        echo "Added rule for port $input"
    fi
done

# Log the dropped packets
iptables -A INPUT -j LOG --log-prefix "DROPPED: "

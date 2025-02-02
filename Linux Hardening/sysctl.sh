echo "Hardening Sysctl..."
cp /etc/sysctl.conf /etc/sysctl.conf.bak
cp "~/USC-CCDC-Tools/Linux Hardening/configs/sysctl.conf" /etc/sysctl.conf
sudo sysctl -e -p /etc/sysctl.conf
echo "Sysctl hardened!"

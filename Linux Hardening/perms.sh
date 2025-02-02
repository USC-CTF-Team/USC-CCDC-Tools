chmod 600 /etc/sudoers
chmod 600 /etc/sudoers.d/*
chmod 644 /etc/passwd
chmod 600 /etc/shadow
chmod 644 /etc/ssh/sshd_config
chown root:root /etc/passwd
chown root:root /etc/shadow
chown root:root /etc/group
chown root:shadow /etc/gshadow-
chmod o-rwx,g-rw /etc/gshadow-
chmod o-rwx,g-rw /etc/shadow-
chmod u-x,go-wx /etc/passwd-
chmod 640 /etc/pam.d/common-password /etc/pam.d/common-auth
chmod 600 ~/.ssh/authorized_keys
#find suid binaries (output to file for documentation purposes)
find / -perm /u=s > ~/suidbinaries.txt
#remove suid bits
cat "~/USC-CCDC-Tools/Linux Hardening/configs/suid.list" | xargs > ~/suid.txt
for i in $(cat ~/suid.txt);
do
  chmod ugo-s /bin/"$i"
done

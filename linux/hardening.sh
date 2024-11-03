#!/bin/sh

# Detect package manager
if command -v apt-get >/dev/null 2>&1; then
    PKG_MANAGER="apt-get"
    PKG_UPDATE="$PKG_MANAGER update"
    PKG_UPGRADE="$PKG_MANAGER upgrade -y"
    PKG_INSTALL="$PKG_MANAGER install -y"
elif command -v dnf >/dev/null 2>&1; then
    PKG_MANAGER="dnf"
    PKG_UPDATE="$PKG_MANAGER check-update"
    PKG_UPGRADE="$PKG_MANAGER upgrade -y"
    PKG_INSTALL="$PKG_MANAGER install -y"
elif command -v yum >/dev/null 2>&1; then
    PKG_MANAGER="yum"
    PKG_UPDATE="$PKG_MANAGER check-update"
    PKG_UPGRADE="$PKG_MANAGER upgrade -y"
    PKG_INSTALL="$PKG_MANAGER install -y"
elif command -v pacman >/dev/null 2>&1; then
    PKG_MANAGER="pacman"
    PKG_UPDATE="$PKG_MANAGER -Sy"
    PKG_UPGRADE="$PKG_MANAGER -Syu --noconfirm"
    PKG_INSTALL="$PKG_MANAGER -S --noconfirm"
else
    echo "Unsupported package manager. Exiting."
    exit 1
fi


# Update and upgrade
echo "Updating system..."
$PKG_UPDATE
$PKG_UPGRADE

# Configure fail2ban
echo "Configuring fail2ban..."
if [ ! -f /etc/fail2ban/jail.local ]; then
    cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
fi
sed -i 's/bantime  = 10m/bantime  = 1h/' /etc/fail2ban/jail.local
systemctl enable fail2ban
systemctl start fail2ban

# Secure SSH
echo "Configuring ssh..."
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
systemctl restart sshd
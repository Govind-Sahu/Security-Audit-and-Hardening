#!/bin/bash

# Security Audit and Hardening Script for Linux Servers

# Output file for report
REPORT_FILE="security_audit_report.txt"

# Initialize the report
echo "Security Audit and Hardening Report" > $REPORT_FILE
echo "Generated on: $(date)" >> $REPORT_FILE
echo "----------------------------------" >> $REPORT_FILE

# Function to list all users and groups
function audit_users_and_groups {
  echo "[+] Auditing Users and Groups" | tee -a $REPORT_FILE
  echo "Users on the server:" >> $REPORT_FILE
  cut -d: -f1 /etc/passwd >> $REPORT_FILE
  echo "Groups on the server:" >> $REPORT_FILE
  cut -d: -f1 /etc/group >> $REPORT_FILE
  echo "Users with UID 0 (non-root):" >> $REPORT_FILE
  awk -F: '($3 == "0") {print}' /etc/passwd | grep -v '^root' >> $REPORT_FILE
  echo "Users without passwords or with weak passwords:" >> $REPORT_FILE
  cat /etc/shadow | awk -F: '($2 == "" || $2 == "!!") {print $1}' >> $REPORT_FILE
  echo "" >> $REPORT_FILE
}

# Function to check file and directory permissions
function audit_file_permissions {
  echo "[+] Auditing File and Directory Permissions" | tee -a $REPORT_FILE
  echo "World-writable files:" >> $REPORT_FILE
  find / -type f -perm -o+w -ls 2>/dev/null >> $REPORT_FILE
  echo "World-writable directories:" >> $REPORT_FILE
  find / -type d -perm -o+w -ls 2>/dev/null >> $REPORT_FILE
  echo ".ssh directories with insecure permissions:" >> $REPORT_FILE
  find / -type d -name ".ssh" -exec ls -ld {} \; | awk '$1 !~ /drwx------/' >> $REPORT_FILE
  echo "Files with SUID or SGID bits set:" >> $REPORT_FILE
  find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; >> $REPORT_FILE
  echo "" >> $REPORT_FILE
}

# Function to audit running services
function audit_services {
  echo "[+] Auditing Running Services" | tee -a $REPORT_FILE
  echo "All running services:" >> $REPORT_FILE
  service --status-all | grep + >> $REPORT_FILE
  echo "Unauthorized or unnecessary services:" >> $REPORT_FILE
  UNAUTHORIZED_SERVICES=("telnet" "rsh" "rexec" "ypbind" "tftp" "vsftpd")
  for svc in "${UNAUTHORIZED_SERVICES[@]}"; do
    if systemctl is-active --quiet $svc; then
      echo "$svc is running" >> $REPORT_FILE
    fi
  done
  echo "Critical services status (sshd, iptables):" >> $REPORT_FILE
  systemctl status sshd iptables | grep Active >> $REPORT_FILE
  echo "" >> $REPORT_FILE
}

# Function to audit firewall and network configurations
function audit_firewall_and_network {
  echo "[+] Auditing Firewall and Network Configurations" | tee -a $REPORT_FILE
  echo "Active firewall rules:" >> $REPORT_FILE
  iptables -L -n -v >> $REPORT_FILE
  echo "Open ports and services:" >> $REPORT_FILE
  netstat -tulpn | grep LISTEN >> $REPORT_FILE
  echo "IP forwarding enabled:" >> $REPORT_FILE
  sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding >> $REPORT_FILE
  echo "" >> $REPORT_FILE
}

# Function to check public vs private IPs
function audit_ip_configuration {
  echo "[+] Auditing IP Configuration" | tee -a $REPORT_FILE
  ip -4 addr show | grep inet | awk '{print $2}' | while read line; do
    ip=$(echo $line | cut -d'/' -f1)
    if [[ $ip =~ ^10\.|^172\.16\.|^192\.168\. ]]; then
      echo "Private IP detected: $ip" >> $REPORT_FILE
    else
      echo "Public IP detected: $ip" >> $REPORT_FILE
    fi
  done
  echo "" >> $REPORT_FILE
}

# Function to check for security updates
function check_security_updates {
  echo "[+] Checking for Security Updates" | tee -a $REPORT_FILE
  if command -v apt-get &> /dev/null; then
    apt-get -s upgrade | grep "^Inst" | grep -i securi >> $REPORT_FILE
  elif command -v yum &> /dev/null; then
    yum check-update --security >> $REPORT_FILE
  fi
  echo "" >> $REPORT_FILE
}

# Function to monitor logs for suspicious activity
function monitor_logs {
  echo "[+] Monitoring Logs for Suspicious Activity" | tee -a $REPORT_FILE
  grep "Failed password" /var/log/auth.log | tail -10 >> $REPORT_FILE
  grep "Invalid user" /var/log/auth.log | tail -10 >> $REPORT_FILE
  echo "" >> $REPORT_FILE
}

# Function to harden the server
function harden_server {
  echo "[+] Hardening Server" | tee -a $REPORT_FILE
  echo "Configuring SSH for key-based authentication and disabling root login." >> $REPORT_FILE
  sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
  sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
  systemctl reload sshd
  echo "Disabling IPv6." >> $REPORT_FILE
  sysctl -w net.ipv6.conf.all.disable_ipv6=1
  echo "Configuring firewall rules." >> $REPORT_FILE
  iptables -P INPUT DROP
  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A INPUT -p tcp --dport 22 -j ACCEPT
  iptables -A INPUT -i lo -j ACCEPT
  iptables-save > /etc/iptables/rules.v4
  echo "Enabling unattended-upgrades." >> $REPORT_FILE
  apt-get install unattended-upgrades -y
  dpkg-reconfigure --priority=low unattended-upgrades
  echo "" >> $REPORT_FILE
}

# Run all audits and hardening steps
audit_users_and_groups
audit_file_permissions
audit_services
audit_firewall_and_network
audit_ip_configuration
check_security_updates
monitor_logs
harden_server

echo "[+] Security Audit and Hardening Completed. Check the report at $REPORT_FILE"

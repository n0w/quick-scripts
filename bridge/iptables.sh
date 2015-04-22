#!/bin/sh

# 2014 Angel Suarez.B Martin (n0w)
# asuarezbm@gmail.com

# IPtables rules for malware analysis

LAN="10.49.33.0/24"
GWAY="10.49.33.1"
BRif1="eth0"
BRif2="eth1"
# Definimos la cadena para aplicar (log, drop) por defecto
echo "[+] Aplicando reglas de iptables..."
iptables -N LOGDROP
iptables -A LOGDROP -j LOG --log-level 4 --log-prefix "br0 DROP:"
iptables -A LOGDROP -j DROP

# Definimos la cadena para aplicar (log, forward)
iptables -N LOGFWD
iptables -A LOGFWD -j LOG --log-level 4 --log-prefix "br0 FWD:"
iptables -A LOGFWD -m physdev --physdev-is-bridged -m state --state ESTABLISHED,RELATED -j ACCEPT

# Bloqueamos todo el trafico tipico de Windows
# RPC, DCE, Gusanos varios...
echo " |>  TCP-UDP 135:139 (RCP,DCE,..) > LOG&DROP"
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p tcp --dport 135:139 -j LOGDROP
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p udp --dport 135:139 -j LOGDROP

# SMB
echo " |>  TCP-UDP 445 (SMB) > LOG&DROP"
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p tcp --dport 445 -j LOGDROP
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p udp --dport 445 -j LOGDROP

# MSSQL
echo " |>  TCP-UDP 1433:1434 (MSSQL) > LOG&DROP"
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p tcp --dport 1433:1434 -j LOGDROP
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p udp --dport 1433:1434 -j LOGDROP

# LDAP over TLS/SSL
echo " |>  TCP-UDP 636 (LDAP_SSL) > LOG&DROP"
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p tcp --dport 636 -j LOGDROP
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p udp --dport 636 -j LOGDROP

# LDAP
echo " |>  TCP-UDP 389 (LDAP) > LOG&DROP"
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p tcp --dport 389 -j LOGDROP
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p udp --dport 389 -j LOGDROP

# IMAP 
echo " |>  TCP 143 (IMAP) > LOG&DROP"
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p tcp --dport 143 -j LOGDROP

# IMAP over SSL
echo " |>  TCP 993 (IMAP_SSL) > LOG&DROP"
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p tcp --dport 993 -j LOGDROP

# POP3
echo " |>  TCP 110 (POP3) > LOG&DROP"
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p tcp --dport 110 -j LOGDROP

# POP3_SSL
echo " |>  TCP 995 (POP3_SSL) > LOG&DROP"
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p tcp --dport 995 -j LOGDROP

# Apple File Sharing Protocol
echo " |>  TCP 548 (AFP) > LOG&DROP" 
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p tcp --dport 548 -j LOGDROP

# Kerberos
echo " |>  TCP-UDP 88 (KERBEROS) > LOG&DROP"
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p tcp --dport 88 -j LOGDROP
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p udp --dport 88 -j LOGDROP
 
# Exchange X.400/X.500
echo " |>  TCP 102 (EXCHANGE X.400/X.500) > LOG&DROP"
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p tcp --dport 102 -j LOGDROP

# RDP 
echo " |>  TCP 3389 (IMAP) > LOG&DROP"
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p tcp --dport 3389 -j LOGDROP

# NNTP
echo " |>  TCP 119 (NNTP) > LOG&DROP"
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p tcp --dport 119 -j LOGDROP

# NNTP over SSL
echo " |>  TCP 563 (NNTP/SSL) > LOG&DROP"
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p tcp --dport 563 -j LOGDROP

# SNMP
echo " |>  TCP&UDP 161:162 (SNMP) > LOG&DROP"
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p tcp --dport 161:162 -j LOGDROP
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p udp --dport 161:162 -j LOGDROP

#WINS
echo " |>  TCP&UDP 42 (WINS) > LOG&DROP"
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p tcp --dport 42 -j LOGDROP
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p udp --dport 42 -j LOGDROP

# protect telnet, ftp, ssh, and smtp
echo " |>  TCP 22,23,25 (TELNET,FTP,SSH,SMTP) > LOG&DROP"
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p tcp --dport 23 -j LOGDROP
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p tcp --dport 22 -j LOGDROP
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p tcp --dport 25 -j LOGDROP
iptables -A FORWARD -m physdev --physdev-in $BRif2 -p tcp -d $LAN --dport 20:25 -j LOGDROP

# SSDP
echo " |>  UDP 1900,2869,5000 (SSDP) > LOG&DROP"
iptables -A FORWARD -m physdev --physdev-in $BRif2 -d 239.255.255.250 -p udp --dport 1900 -j LOGDROP
iptables -A FORWARD -m physdev --physdev-in $BRif2 -d 239.255.255.250 -p udp --dport 2869 -j LOGDROP
iptables -A FORWARD -m physdev --physdev-in $BRif2 -d 239.255.255.250 -p udp --dport 5000 -j LOGDROP

# SRVLOC
echo " |>  UDP 427 (SRVLOC) > LOG&DROP"
iptables -A FORWARD -m physdev --physdev-in $BRif2 -d 239.255.255.253 -p udp --dport 427 -j LOGDROP

# MULTICAST
echo " |>  (MULTICAST) > LOG&DROP"
iptables -A FORWARD -m physdev --physdev-in $BRif2 -d 224.0.0.0/8 -p udp -j LOGDROP
iptables -A FORWARD -m physdev --physdev-in $BRif2 -d 225.0.0.0/8 -p udp -j LOGDROP
iptables -A FORWARD -m physdev --physdev-in $BRif2 -d 232.0.0.0/8 -p udp -j LOGDROP
iptables -A FORWARD -m physdev --physdev-in $BRif2 -d 233.0.0.0/8 -p udp -j LOGDROP
iptables -A FORWARD -m physdev --physdev-in $BRif2 -d 234.0.0.0/8 -p udp -j LOGDROP
iptables -A FORWARD -m physdev --physdev-in $BRif2 -d 239.0.0.0/8 -p udp -j LOGDROP

# Forward all other traffic
echo "[+]  << ALL OTHER TRAFFIC IS ALLOWED (!) >> LOG&FORWARD"
iptables -A FORWARD -j LOGFWD

#!/bin/sh

# 2014 Angel Suarez.B Martin (n0w)
# asuarezbm@gmail.com

# Script para apagar un bridge l2 siguiendo el siguiente esquema
#  ___________________       ____________________________         __________ _ _
# +                   +     +                            +       ·  
# |  Suspect Machine  |=====|(eth1) Bridge Machine (eth0)|======|   LAN
# +___________________+     +____________________________+       ·__________ _ _
#
#
# Version 1.0 06/11/2014

# Variables

BRif1="eth0"
BRif2="eth1"
LAN="10.49.33.0/24"
GWAY="10.49.33.1"

# Definimos el bridge
echo "[+] Apagando interfaces..."
ip link set $BRif1 down
ip link set $BRif2 down
ip link set br0 down
echo "[+] Borrando puente..."
brctl delif br0 $BRif1
brctl delif br0 $BRif2
brctl delbr br0


# Definimos la cadena para aplicar (log, drop) por defecto
echo "[+] Quitando reglas de iptables..."
iptables -F
#iptables -X LOGDROP
iptables -X LOGFWD
























































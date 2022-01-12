#!/bin/bash

ip addr sh

git clone https://github.com/scipag/vulscan scipag_vulscan
ln -s `pwd`/scipag_vulscan /usr/share/nmap/scripts/vulscan

mkdir ~/scans

# 10.168.27.10
ipaddr=10.168.27.10
ipstr=$(echo $ipaddr | tr '.' '-')
mkdir=~/scans/$ipstr
nmap -sV -p- --version-all $ipaddr > ~/scans/$ipstr/$ipstr.sV-p-.nmap
for port in 135 139 389 445 686; do
    nmap -sV -p $port --version-all --script=vulscan/vulscan.nse --script-args vulscandb=cve.csv $ipaddr > ~/scans/$ipstr/$ipstr.vulscan-p$port.nmap
done
nmap -sV -p 49152-65535 --version-all --script=vulscan/vulscan.nse --script-args vulscandb=cve.csv $ipaddr > ~/scans/$ipstr/$ipstr.vulscan-ephemeral.nmap
nmap -O --fuzzy $ipaddr > ~/scans/$ipstr/$ipstr.os.nmap

# 10.168.27.14
ipaddr=10.168.27.14
ipstr=$(echo $ipaddr | tr '.' '-')
mkdir=~/scans/$ipstr
nmap -sV -p- --version-all $ipaddr > ~/scans/$ipstr/$ipstr.sV-p-.nmap
for port in 22 9090; do
    nmap -sV -p $port --version-all --script=vulscan/vulscan.nse --script-args vulscandb=cve.csv $ipaddr > ~/scans/$ipstr/$ipstr.vulscan-p$port.nmap
done
nmap -O --fuzzy $ipaddr > ~/scans/$ipstr/$ipstr.os.nmap

# 10.168.27.15
ipaddr=10.168.27.15
ipstr=$(echo $ipaddr | tr '.' '-')
mkdir=~/scans/$ipstr
nmap -sV -p- --version-all $ipaddr > ~/scans/$ipstr/$ipstr.sV-p-.nmap
for port in 7 9 13 17 19 21 80 135 139 445; do
    nmap -sV -p $port --version-all --script=vulscan/vulscan.nse --script-args vulscandb=cve.csv $ipaddr > ~/scans/$ipstr/$ipstr.vulscan-p$port.nmap
done
for port in 7 9 13 17 19; do
    nmap -sU -p $port $ipaddr > ~/scans/$ipstr/$ipstr.sU-p$port.nmap
done
nmap -sV -p 49152-65535 --version-all --script=vulscan/vulscan.nse --script-args vulscandb=cve.csv $ipaddr > ~/scans/$ipstr/$ipstr.vulscan-ephemeral.nmap
nmap -O --fuzzy $ipaddr > ~/scans/$ipstr/$ipstr.os.nmap

# 10.168.27.20
ipaddr=10.168.27.20
ipstr=$(echo $ipaddr | tr '.' '-')
mkdir=~/scans/$ipstr
nmap -sV -p- --version-all $ipaddr > ~/scans/$ipstr/$ipstr.sV-p-.nmap
for port in 22; do
    nmap -sV -p $port --version-all --script=vulscan/vulscan.nse --script-args vulscandb=cve.csv $ipaddr > ~/scans/$ipstr/$ipstr.vulscan-p$port.nmap
done
nmap -O --fuzzy $ipaddr > ~/scans/$ipstr/$ipstr.os.nmap

# 10.168.27.132
ipaddr=10.168.27.132
ipstr=$(echo $ipaddr | tr '.' '-')
mkdir=~/scans/$ipstr
nmap -sV -p- --version-all $ipaddr > ~/scans/$ipstr/$ipstr.sV-p-.nmap
for port in 22; do
    nmap -sV -p $port --version-all --script=vulscan/vulscan.nse --script-args vulscandb=cve.csv $ipaddr > ~/scans/$ipstr/$ipstr.vulscan-p$port.nmap
done
nmap -O --fuzzy $ipaddr > ~/scans/$ipstr/$ipstr.os.nmap


# Upload results to transfer.sh
tar cvf scans.tar ~/scans
curl --upload-file scans.tar https://transfer.sh/scans.tar
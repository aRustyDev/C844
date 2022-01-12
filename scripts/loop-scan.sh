#!/bin/bash

ip addr sh

git clone https://github.com/scipag/vulscan scipag_vulscan
ln -s `pwd`/scipag_vulscan /usr/share/nmap/scripts/vulscan

mkdir ~/scans

for d in 10 14 15 20 132; do 
    ipaddr=10.168.27.$d
    ipstr=$(echo $ipaddr | tr '.' '-')
    mkdir=~/scans/$ipstr
    nmap -O --fuzzy $ipaddr > ~/scans/$ipstr/$ipstr.os.nmap
    nmap -sV -p- --version-all $ipaddr > ~/scans/$ipstr/$ipstr.sV-p-.nmap
    case $d in 
        10)
            ports=(135 139 389 445 686)
            ;;
        14)
            ports=(22 9090)
            ;;
        15)
            ports=(7 9 13 17 19 21 80 135 139 445)
            ;;
        20)
            ports=(22)
            ;;
        132)
            ports=(22 9090)
           ;; 
    esac
    for port in $ports; do
        nmap -sV -p $port --version-all --script=vulscan/vulscan.nse --script-args vulscandb=cve.csv $ipaddr > ~/scans/$ipstr/$ipstr.vulscan-p$port.nmap
    done
    if $d -eq 15; do
        for port in 7 9 13 17 19; do
            nmap -sU -p $port $ipaddr > ~/scans/$ipstr/$ipstr.sU-p$port.nmap
        done
    fi
done

# Upload results to transfer.sh
tar cvf scans.tar ~/scans
curl --upload-file scans.tar https://transfer.sh/scans.tar
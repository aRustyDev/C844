#!/bin/bash
##############
# Variables
##############
vulndb="cve.csv"
target_subnet="10.168.27.1/24"
vulscan_src="https://github.com/scipag/vulscan"
vulscan_dst="/opt/scipag_vulscan"
subnet=$(ip addr sh | grep eth0 | awk '/inet/ {print $2}')
gateways=($(ip route get 8.8.8.8 | awk '{print $3, $7}'))

dnssrv=$(cat /etc/resolv.conf | grep nameserver | awk '{print $2}')
kern=$(uname -a)
hostname=$(hostname)
me=$(whoami)
whoelse=$(who)

##############
# Colors
##############
black=$(tput setaf 0)
red=$(tput setaf 1)
yellow=$(tput setaf 3)
green=$(tput setaf 2)
blue=$(tput setaf 4)
magenta=$(tput setaf 5)
cyan=$(tput setaf 6)
white=$(tput setaf 7)
powder_blue=$(tput setaf 153)
lime_yellow=$(tput setaf 190)

bright=$(tput bold)
blink=$(tput blink)

normal=$(tput sgr0)
reverse=$(tput smso) # Reverse background and foreground colors
underline=$(tput smul)


printf "|-- ${blue}== Setup ==${normal}\n"
printf "|   |-- ${cyan}Directory${normal}   "
(mkdir ~/scans 2> /dev/null && \
printf ": ${green}Created${normal}  : '~/scans'\n") || \
printf ": ${green}Located${normal}  : ''~/scans'\n"


# Check for VulScan and Clone if not present
    printf "|   |-- ${cyan}Tools${normal}\n"
    printf "|   |   |-- Vulscan "
    if [[ ! -z $(find /opt -type d 2> /dev/null | grep vulscan) ]]; then 
        printf ": ${green}Located${normal}\n"
    else
        printf "\n|   |   |   |-- ${yellow}Cloning${normal} "
        git clone --quiet $vulscan_src $vulscan_dst 2> ~/scans/git.log
        printf ": ${green}Complete${normal}\n"
        printf "|   |   |   |-- src: https://github.com/scipag/vulscan\n"
        printf "|   |   |   |-- dst: /opt/scipag_vulscan\n"
        printf "|   |   |   |-- log: ~/scans/git.log\n"
        if [ $(find /usr/share/nmap/scripts -type l 2> /dev/null | grep vulscan) ]; then # if vulscan symlinked elsewhere, remove it
            rm -f $(find /usr/share/nmap/scripts -type l 2> /dev/null | grep vulscan)
        fi
    fi
    printf "|   |   |-- NSE     "
    if [[ ! -z $(find /usr/share/nmap/scripts -type l 2> /dev/null | grep vulscan) ]]; then # if vulscan repo symlinked
        printf ": ${green}Linked${normal}\n"
    else
        ln -s /opt/scipag_vulscan /usr/share/nmap/scripts/vulscan
        printf ": ${green}Linked${normal}\n"
    fi

# Tee Host info 
    printf "|-- ${blue}== Host Info ==${normal}\n" | tee ~/scans/host.info
    printf "|   |-- ${cyan}User${normal}\n" | tee -a ~/scans/host.info
    printf "|   |   |-- WhoAmI      : $me\n" | tee -a ~/scans/host.info
    printf "|   |   |-- Who         : $whoelse\n|   |\n" | tee -a ~/scans/host.info
    printf "|   |-- ${cyan}Host${normal}\n" | tee -a ~/scans/host.info
    printf "|   |   |-- Kernel      : $kern\n" | tee -a ~/scans/host.info
    printf "|   |   |-- Hostname    : $hostname\n|   |\n" | tee -a ~/scans/host.info
    printf "|   |-- ${cyan}Networking${normal}\n" | tee -a ~/scans/host.info
    printf "|   |   |-- Default GW  : ${gateways[1]}\n" | tee -a ~/scans/host.info
    printf "|   |   |-- Internet GW : ${gateways[0]}\n" | tee -a ~/scans/host.info
    printf "|   |   |-- Subnet      : $subnet\n" | tee -a ~/scans/host.info
    printf "|   |   |-- NameServer  : $dnssrv\n|   |\n" | tee -a ~/scans/host.info

# Initial Scan, get IP's that are up.
    printf "|-- ${blue}== Scanning Subnet ==${normal}\n"
    printf "|   |-- ${cyan}Target Subnet${normal}   : $target_subnet\n" 
    alive=($(nmap -n -sn $target_subnet -oG - | awk '/Up$/{print $2}'))
    printf "|   |-- ${cyan}Alive Hosts${normal}\n" 
    for i in "${alive[@]}"; do
        printf "|   |   |-- ${lime_yellow}$i${normal}\n" 
    done
    printf "|   |\n" 

# Run through these ip's
    for ipaddr in "${alive[@]}"; do 
        ipstr=$(echo $ipaddr | tr '.' '-')
        
        printf "|-- ${blue}== Scanning [${white}$ipaddr${blue}] ==${normal}\n"

        printf "|   |-- ${cyan}Directory${normal}                            "
        (mkdir ~/scans/$ipstr 2> /dev/null && \
        printf ": ${green}Created${normal}  : '~/scans/$ipstr'\n") || \
        printf ": ${green}Located${normal}  : '~/scans/$ipstr'\n"
        
#         # This needs some work to be production ready. (How to tell if directly connected, or connected via what. Need better summary.
#         printf "|   |-- Testing Route\n"
#         iproute=$(if [ $(ip route get $ipaddr | awk '{print $5}') -eq $(echo $subnet | cut -d'/' -f1)) ]; then  && \
#         iphost=$(host $ipaddr) && \
#         printf "|   |   |-- Route Test Complete : '~/scans/$ipstr/$ipstr.info'\n"  
#         printf "|   |   |   |-- Route   : $iproute\n"
#         printf "|   |   |   |-- Hostname: $iphost\n|\n"
#         echo "Route   : $iproute" > ~/scans/$ipstr/$ipstr.info
#         echo "Hostname: $iphost" >> ~/scans/$ipstr/$ipstr.info

    # OS Scanning
        printf "|   |-- ${cyan}Scanning OS${normal}                          "
        nmap -O --fuzzy $ipaddr > ~/scans/$ipstr/$ipstr.os.nmap && \
        printf ": ${green}Complete${normal} : '~/scans/$ipstr/$ipstr.os.nmap'\n"    

    # Service Scanning
        printf "|   |-- ${cyan}Scanning for Services${normal}                "

        nmap -sV -p0- --version-all -oG ~/scans/$ipstr/$ipstr.sV-p-.grep $ipaddr > ~/scans/$ipstr/$ipstr.sV-p-.nmap && \
        cat ~/scans/$ipstr/$ipstr.sV-p-.grep | grep Ports | grep -oE " [1234567890]+/" | grep -oE "[1234567890]+" > ~/scans/port.tmp && \
        cat ~/scans/$ipstr/$ipstr.sV-p-.grep | grep Ports | tr ',' '\n' | grep -oE "//.+//" | grep -oE "[^/]+" > ~/scans/serv.tmp
        
        printf ": ${green}Complete${normal} : '~/scans/$ipstr/$ipstr.sV-p-.nmap'\n"    
        
    # Vulnerability Scanning
        printf "|   |-- ${cyan}Scanning Services for Vulns${normal} :\n" # if ports NE null
        printf "|   |   |-- VulnDB    : %s\n" $(echo $vulndb | cut -d. -f1)
        printf "|   |   |-- Port      :\n"
        exec 5< ~/scans/port.tmp && exec 6< ~/scans/serv.tmp
        while read port <&5 && read serv <&6; do
            printf "|   |   |   |-- ${cyan}%5d${normal} " $port
            printf ": ${cyan}%-20s${normal} " $serv
            nmap -sV -p $port --version-all --script=vulscan/vulscan.nse --script-args vulscandb=$vulndb $ipaddr > ~/scans/$ipstr/$ipstr.vulscan-p$port.nmap
            printf ": ${green}Complete${normal} : '~/scans/$ipstr/$ipstr.vulscan-p$port.nmap'\n"
            # echo "${red}CMD RUN${normal} :: ${lime_yellow}nmap -sV -p $port --version-all --script=vulscan/vulscan.nse --script-args vulscandb=$vulndb $ipaddr > ~/scans/$ipstr/$ipstr.vulscan-p$port.nmap${normal}"
        done
    done

# This parts static, won't play well in new subnet.
    printf "|-- ${magenta}Scanning UDP ports${normal}\n"
    for port in 7 9 13 17 19; do
        printf "|   |-- Port   : %5d " $port
        nmap -sU -p $port "10.168.27.15" > ~/scans/10-168-27-15/10-168-27-15.sU-p$port.nmap
        printf ": ${green}Complete${normal} : '~/scans/10-168-27-15/10-168-27-15.sU-p$port.nmap'\n"  
    done

# Tar & Upload results to transfer.sh
    tar cvf scans.tar ~/scans
    curl --upload-file scans.tar https://transfer.sh/scans.tar
#!/usr/bin/env bash

# Program: archtorify.sh
# Version: 1.8.3
# Operating System: Arch Linux
# Description: Transparent proxy through Tor
# Dependencies: tor
#
# Copyright (C) 2015-2017 Brainfuck

# GNU GENERAL PUBLIC LICENSE
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


# Program's informations
PROGRAM="archtorify"
VERSION="1.8.3"
AUTHOR="Brainfuck"
GIT_URL="https://github.com/brainfucksec/archtorify"

# define colors
export red=$'\e[0;91m'
export green=$'\e[0;92m'
export blue=$'\e[0;94m'
export white=$'\e[0;97m'
export cyan=$'\e[0;96m'
export endc=$'\e[0m'


# banner
banner() {
printf "${white}
*********************************************
*                                           *
*  _____         _   _           _ ___      *
* |  _  |___ ___| |_| |_ ___ ___|_|  _|_ _  *
* |     |  _|  _|   |  _| . |  _| |  _| | | *
* |__|__|_| |___|_|_|_| |___|_| |_|_| |_  | *
*                                     |___| *
*                                           *
*********************************************

Version: $VERSION
Author: $AUTHOR
$GIT_URL${endc}\n"
}


# check if the program run as a root
check_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        printf "\n${red}%s${endc}\n" "[ FAILED ] Please run this program as a root!" 2>&-
        exit 1
    fi
}


# display Program and Tor version then exit
print_version() {
    printf "${white}%s${endc}\n" "$PROGRAM version $VERSION"
    printf "${white}%s${endc}\n" "$(tor --version)"
    exit 0
}


## Functions for firewall ufw
# check ufw status:
# if installed and/or active disable it
# if aren't installed, do nothing, don't display
# nothing to user, simply jump to next function
disable_ufw() {
    if hash ufw 2>/dev/null; then
        if ufw status | grep -q active$; then
            printf "${blue}%s${endc} ${green}%s${endc}\n" \
                "::" "Firewall ufw is active, disabling..."
            ufw disable
            sleep 3
        else
            ufw status | grep -q inactive$;
            printf "${blue}%s${endc} ${green}%s${endc}\n" \
                "::" "Firewall ufw is inactive, continue..."
        fi
    fi
}


# enable ufw
# if ufw isn't installed, do nothing and jump to
# the next function
enable_ufw() {
    if hash ufw 2>/dev/null; then
        if ufw status | grep -q inactive$; then
            printf "${blue}%s${endc} ${green}%s${endc}\n" \
                "::" "Enabling firewall ufw"
            ufw enable
            sleep 3
        fi
    fi
}


## Check default configurations
# check if archtorify is properly configured, begin ...
check_default() {
    # check dependencies (tor)
    declare -a dependencies=("tor");
    for package in "${dependencies[@]}"; do
        if ! hash "$package" 2>/dev/null; then
            printf "${red}%s${endc}\n" \
                "[ FAILED ] '$package' isn't installed, exit";
            exit 1
        fi
    done

    ## Check file: "/usr/lib/systemd/system/tor.service"
    # ref: https://wiki.archlinux.org/index.php/tor#Transparent_Torification
    grep -q -x '\[Service\]' /usr/lib/systemd/system/tor.service
    VAR1=$?

    grep -q -x 'User=root' /usr/lib/systemd/system/tor.service
    VAR2=$?

    grep -q -x 'Group=root' /usr/lib/systemd/system/tor.service
    VAR3=$?

    grep -q -x 'Type=simple' /usr/lib/systemd/system/tor.service
    VAR4=$?

    # if it is not already set, set it now
    if [ $VAR1 -ne 0 ] || [ $VAR2 -ne 0 ] || [ $VAR3 -ne 0 ] || [ $VAR4 -ne 0 ]; then
        printf "\n${blue}%s${endc} ${green}%s${endc}" \
            "::" "Setting file: /usr/lib/systemd/system/tor.service.. "
        # backup original file
        cp -vf /usr/lib/systemd/system/tor.service /usr/lib/systemd/system/tor.service.backup
        
        # write new settings
        echo '[Unit]
Description=Anonymizing Overlay Network
After=network.target

[Service]
User=root
Group=root
Type=simple
ExecStart=/usr/bin/tor -f /etc/tor/torrc
ExecReload=/usr/bin/kill -HUP $MAINPID
KillSignal=SIGINT
LimitNOFILE=8192
PrivateDevices=yes

[Install]
WantedBy=multi-user.target' > /usr/lib/systemd/system/tor.service
# EOF
        printf "${green}%s${endc}\n" "Done"
    fi

    ## Check permissions of directory: "/var/lib/tor"
    # correct: drwx------  tor tor
    # if the file is not set, exec commands and set it now
    if [[ "$(stat -c '%U' /var/lib/tor)" != "tor" ]] &&
        [[ "$(stat -c '%a' /var/lib/tor)" != "755" ]]; then
        printf "${blue}%s${endc} ${green}%s${endc}" \
            "::" "Setting permissions of directory: /var/lib/tor... "
        # exec 
        chown -R tor:tor /var/lib/tor
        sleep 1
        chmod -R 755 /var/lib/tor
        sleep 1
        systemctl --system daemon-reload

        printf "${green}%s${endc}\n" "Done"
    fi

    ## Check file: "/etc/tor/torrc"
    grep -q -x 'User tor' /etc/tor/torrc
    VAR5=$?

    grep -q -x 'SocksPort 9050' /etc/tor/torrc
    VAR6=$?

    grep -q -x 'DNSPort 53' /etc/tor/torrc
    VAR7=$?

    grep -q -x 'TransPort 9040' /etc/tor/torrc
    VAR8=$?

    # if it is not already set, set it now
    if [ $VAR5 -ne 0 ] || [ $VAR6 -ne 0 ] || [ $VAR7 -ne 0 ] || [ $VAR8 -ne 0 ]; then
        printf "\n${blue}%s${endc} ${green}%s${endc}" "::" "Setting file: /etc/tor/torrc... "
        # backup original file
        cp -f /etc/tor/torrc /etc/tor/torrc.backup
        
        # write new settings
        echo '## Configuration file for Tor
## 
## See "man tor", or https://www.torproject.org/docs/tor-manual.html,
## for more options you can use in this file.
##
## Tor will look for this file in various places based on your platform:
## https://www.torproject.org/docs/faq#torrc

## Logs to /tmp to prevent digital evidence to be stored on disk
Log notice file /tmp/archtorify.log

## The directory for keeping all the keys/etc. By default, we store
## things in $HOME/.tor on Unix, and in Application Data\tor on Windows.
DataDirectory /var/lib/tor

## Still if you cannot start the tor service, run the service using root 
## (this will switch back to the tor user).
User tor

## Transparent Proxy settings
SocksPort 9050
DNSPort 53
TransPort 9040' > /etc/tor/torrc
# EOF
        printf "${green}%s${endc}\n" "Done"
    fi
}


## Start transparent proxy
main() {
    banner
    check_root
    check_default

    # check status of tor.service and stop it if is active (for better security)
    if systemctl is-active tor.service > /dev/null 2>&1; then
        systemctl stop tor.service
    fi

    printf "\n${blue}%s${endc} ${green}%s${endc}\n" "::" "Starting Transparent Proxy"
    disable_ufw
    sleep 3

    ## iptables settings:
    # save iptables rules
    printf "${blue}%s${endc} ${green}%s${endc}" "::" "Backup iptables rules... "
    iptables-save > /opt/iptables.backup
    printf "${green}%s${endc}\n" "Done"
    sleep 2

    # flush current iptables rules
    printf "${blue}%s${endc} ${green}%s${endc}" "::" "Flush iptables rules... "
    iptables -F
    iptables -t nat -F
    printf "${green}%s${endc}\n" "Done"

    # configure system's DNS resolver to use Tor's DNSPort on the loopback interface
    printf "${blue}%s${endc} ${green}%s${endc}\n" \
        "::" "Configure system's DNS resolver to use Tor's DNSPort"
    cp -vf /etc/resolv.conf /opt/resolv.conf.backup
    echo -e 'nameserver 127.0.0.1' > /etc/resolv.conf
    sleep 2

    # write new iptables rules on file: "/etc/iptables/iptables.rules"
    printf "${blue}%s${endc} ${green}%s${endc}" "::" "Set new iptables rules... "

    # NOTE --> add exception rules on iptables for allow traffic on Virtualbox NAT Network 
    # '--ipv4 -A OUTPUT -d 10.0.0.0/8 -j ACCEPT'
    echo '*nat
:PREROUTING ACCEPT [6:2126]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [17:6239]
:POSTROUTING ACCEPT [6:408]

-A PREROUTING ! -i lo -p udp -m udp --dport 53 -j REDIRECT --to-ports 53
-A PREROUTING ! -i lo -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports 9040
-A OUTPUT -o lo -j RETURN
--ipv4 -A OUTPUT -d 192.168.0.0/16 -j RETURN
-A OUTPUT -m owner --uid-owner "tor" -j RETURN
-A OUTPUT -p udp -m udp --dport 53 -j REDIRECT --to-ports 53
-A OUTPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports 9040
COMMIT

*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]

-A INPUT -i lo -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
--ipv4 -A INPUT -p tcp -j REJECT --reject-with tcp-reset
--ipv4 -A INPUT -p udp -j REJECT --reject-with icmp-port-unreachable
--ipv4 -A INPUT -j REJECT --reject-with icmp-proto-unreachable
--ipv6 -A INPUT -j REJECT
--ipv4 -A OUTPUT -d 127.0.0.0/8 -j ACCEPT
--ipv4 -A OUTPUT -d 192.168.0.0/16 -j ACCEPT
--ipv4 -A OUTPUT -d 10.0.0.0/8 -j ACCEPT
--ipv6 -A OUTPUT -d ::1/8 -j ACCEPT
-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A OUTPUT -m owner --uid-owner "tor" -j ACCEPT
--ipv4 -A OUTPUT -j REJECT --reject-with icmp-port-unreachable
--ipv6 -A OUTPUT -j REJECT
COMMIT' >> /etc/iptables/iptables.rules
# EOF
    printf "${green}%s${endc}\n" "Done"
    sleep 4
    
    ## Tor Entry Guards
    # delete file: "/var/lib/tor/state"
    # 
    # When tor.service starting, a new file 'state' it's generated
    # when you connect to Tor network, a new Tor entry guards will be written on this file.
    #
    # TODO: add parameter for selecting this option non-interactively
    # (i.e. archtorify --start --new-guards)
    printf "${blue}%s${endc} ${green}%s${endc}" "::" "Get fresh Tor entry guards? [Y/N]"
    read -p "${green}:${endc} " yn
    case $yn in
        [yY]|[y|Y] )
            rm -v /var/lib/tor/state
            printf "${cyan}%s${endc} ${greebe}%s${endc}\n" \
                "[ OK ]" "When tor.service start, new Tor entry guards will obtained"
            ;;
        *)
            ;;
    esac

    # start tor.service
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Start Tor service... "
    systemctl start tor.service iptables
    sleep 6
    printf "${cyan}%s${endc} ${green}%s${endc}\n" "[ OK ]" "Tor service is active"

    printf "${cyan}%s${endc} ${green}%s${endc}\n" \
        "[ OK ]" "Transparent Proxy activated, your system is under Tor"
    printf "${cyan}%s${endc} ${green}%s${endc}\n" \
        "[ INFO ]" "use '--status' argument for check the program status"
}


## Stop transparent proxy
stop() {
    check_root
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Stopping Transparent Proxy"
    sleep 2

    # flush current iptables rules
    printf "${blue}%s${endc} ${green}%s${endc}" "::" "Flush iptables rules... "
    iptables -F
    iptables -t nat -F
    printf "${green}%s${endc}\n" "Done"

    # restore iptables
    printf "${blue}%s${endc} ${green}%s${endc}" "::" "Restore the default iptables rules... "
    iptables-restore < /opt/iptables.backup
    printf "${green}%s${endc}\n" "Done"
    sleep 3

    # stop tor.service
    printf "${blue}%s${endc} ${green}%s${endc}" "::" "Stop Tor service... "
    systemctl stop tor.service
    printf "${green}%s${endc}\n" "Done"
    sleep 4

    # restore /etc/resolv.conf --> default nameserver
    printf "${blue}%s${endc} ${green}%s${endc}\n" \
        "::" "Restore '/etc/resolv.conf' file with default DNS"
    rm -v /etc/resolv.conf
    cp -vf /opt/resolv.conf.backup /etc/resolv.conf
    sleep 2

    # enable firewall ufw
    enable_ufw
    printf "${cyan}%s${endc} ${green}%s${endc}\n" "[-]" "Transparent Proxy stopped"
}


## Function for check public IP
check_ip() {
    printf "\n${blue}%s${endc} ${green}%s${endc}\n" \
        "::" "Checking your public IP, please wait..."
    # curl request: http://ipinfo.io/geo
    if ! external_ip="$(curl -s -m 10 ipinfo.io/geo)"; then
        printf "${red}%s${endc}\n" "[ FAILED ] curl: HTTP request error!"
        exit 1
    fi
    # print output
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "IP Address Details:"
    printf "${white}%s${endc}\n" "$external_ip" | tr -d '"{}' | sed 's/ //g'
}


## check_status function
# function for check status of program and services:
# check --> tor.service
# check --> public IP
# TODO: check if public IP is Tor exit node (not for security reason but only
# for inform the users :)
check_status () {
    check_root
    # check status of tor.service
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Check current status of Tor service"
    if systemctl is-active tor.service > /dev/null 2>&1; then
        printf "${cyan}%s${endc} ${green}%s${endc}\n" "[ OK ]" "Tor service is active"
    else
        printf "${red}%s${endc}\n" "[-] Tor service is not running! exiting..."
        exit 1
    fi
    # check current public IP
    check_ip
    exit 0
}


## restart tor.service and change IP
restart() {
    check_root
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Restart Tor service and change IP"
    # systemctl stop/start service
    systemctl stop tor.service iptables
    sleep 3
    systemctl start tor.service iptables
    sleep 2
    printf "${cyan}%s${endc} ${green}%s${endc}\n" "[ OK ]" "Tor Exit Node changed"
    # check current public ip
    check_ip
}


# print nice "nerd" help menu'
help_menu() {
    banner

    printf "\n\n${green}%s${endc}\n" "Usage:"
    printf "${white}%s${endc}\n\n"   "------"
    printf "${white}%s${endc} ${red}%s${endc} ${white}%s${endc} ${red}%s${endc}\n" \
        "┌─╼" "$USER" "╺─╸" "$(hostname)"
    printf "${white}%s${endc} ${green}%s${endc}\n" "└───╼" "./$PROGRAM --argument"

    printf "\n${green}%s${endc}\n" "Arguments available:"
    printf "${white}%s${endc}\n" "--------------------"

    printf "${white}%-12s${endc} ${green}%s${endc}\n" "--help"      "show this help message and exit"
    printf "${white}%-12s${endc} ${green}%s${endc}\n" "--start"     "start transparent proxy through tor"
    printf "${white}%-12s${endc} ${green}%s${endc}\n" "--stop"      "reset iptables and return to clear navigation"
    printf "${white}%-12s${endc} ${green}%s${endc}\n" "--status"    "check status of program and services"
    printf "${white}%-12s${endc} ${green}%s${endc}\n" "--checkip"   "check only public IP"
    printf "${white}%-12s${endc} ${green}%s${endc}\n" "--restart"   "restart tor service and change IP"
    printf "${white}%-12s${endc} ${green}%s${endc}\n" "--version"   "display program and tor version then exit"
    exit 0
}


## cases user input
case "$1" in
    --start)
        main
        ;;
    --stop)
        stop
        ;;
    --restart)
        restart
        ;;
    --status)
        check_status
        ;;
    --checkip)
        check_ip
        ;;
    --version)
        print_version
        ;;
    --help)
        help_menu
        ;;
    *)
help_menu
exit 1

esac

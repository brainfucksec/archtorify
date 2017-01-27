#!/bin/bash

# Program: archtorify.sh
# Version: 1.7.0
# Operating System: Arch Linux
# Description: Transparent proxy trough Tor 
# Dependencies: tor, curl
# 
# Copyright (C) 2015, 2016, 2017 Brainfuck 

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


# program / version
_PROGRAM="archtorify"
_VERSION="1.7.0"

# define colors
export red=$'\e[0;91m'
export green=$'\e[0;92m'
export blue=$'\e[0;94m'
export white=$'\e[0;97m'
export endc=$'\e[0m'


# banner
function banner {
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

Transparent Proxy Trough Tor for Arch Linux OS
----------------------------------------------

Version: $_VERSION
Author: Brainfuck${endc}\n"
}


# check if the program run as a root
check_root () {
	if [ "$(id -u)" -ne 0 ]; then
		printf "\n${red}%s${endc}\n" "[ FAILED ] Please run this program as a root!" >&2
		exit 1
	fi
}


# display Program and Tor version then exit
print_version () {
	printf "${white}%s${endc}\n" "$_PROGRAM version $_VERSION"
	printf "${white}%s${endc}\n" "$(tor --version)"
	exit 0
}


# Functions for firewall ufw
# **************************
# check ufw status: 
# if installed and/or active disable it
# if aren't installed, do nothing, don't display
# nothing to user, simply jump to next function
disable_ufw () {
	if hash ufw 2>/dev/null; then
		if ufw status | grep -q active$; then
			printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Firewall ufw is active, disabling..."
			ufw disable
			sleep 3
		else
			ufw status | grep -q inactive$;
			printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Firewall ufw is inactive, continue..."
		fi
	fi
}


# enable ufw 
# if ufw isn't installed, do nothing and jump to
# the next function
enable_ufw () {
	if hash ufw 2>/dev/null; then
		if ufw status | grep -q inactive$; then
			printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Enabling firewall ufw"
			ufw enable
			sleep 3
		fi
	fi
}


# Check default configurations
# ****************************
# check if archtorify is properly configured, begin ...
check_default () {
	# check dependencies (tor, curl)
	command -v tor > /dev/null 2>&1 ||
	{ printf >&2 "\n${red}%s${endc}\n" "[ FAILED ] tor isn't installed, exiting..."; exit 1; }

	command -v curl > /dev/null 2>&1 ||
	{ printf >&2 "\n${red}%s${endc}\n" "[ FAILED ] curl isn't installed, exiting..."; exit 1; }

	# check file: "/usr/lib/systemd/system/tor.service"
	# example config file: "archtorify/tor.service-example"
	grep -q -x '\[Service\]' /usr/lib/systemd/system/tor.service
	VAR1=$?

	grep -q -x 'User=root' /usr/lib/systemd/system/tor.service
	VAR2=$?

	grep -q -x 'Group=root' /usr/lib/systemd/system/tor.service
	VAR3=$?

	grep -q -x 'Type=simple' /usr/lib/systemd/system/tor.service
	VAR4=$?

	if [ $VAR1 -ne 0 ] || [ $VAR2 -ne 0 ] || [ $VAR3 -ne 0 ] || [ $VAR4 -ne 0 ]; then
		printf "\n${red}%s${endc} ${white}%s${endc}\n" "[ FAILED ] Please add this lines at file:" "/usr/lib/systemd/system/tor.service" 
		printf "${white}%s${endc}\n" "[Service]"
		printf "${white}%s${endc}\n" "User=root"
		printf "${white}%s${endc}\n" "Group=root"
		printf "${white}%s${endc}\n\n" "Type=simple"
		printf "${green}%s${endc} ${white}%s${endc}\n" "You can copy configuration from:" "archtorify/tor.service-example"
	exit 1
	fi

	# Check privilege of directory: "/var/lib/tor"
	#
	# ls -alh /var/lib/ | grep "tor"
	# correct permissions: drwx------  tor tor
	if [ "$(stat -c '%U' /var/lib/tor)" != "tor" ] &&
		[ "$(stat -c '%a' /var/lib/tor)" != "755" ]; then
		printf "${red}%s${endc} ${white}%s${endc}\n" "[ FAILED ] Please give the right permissions and owner of directory:" "/var/lib/tor folder"
		printf "${white}%s${endc}\n" "# chown -R tor:tor /var/lib/tor"
		printf "${white}%s${endc}\n" "# chmod -R 755 /var/lib/tor"
		printf "${white}%s${endc}\n" "# systemctl --system daemon-reload"
	exit 1
	fi

	# Check file: "/etc/tor/torrc"
	#
	# User tor
	# SocksPort 9050
	# DNSPort 53
	# TransPort 9040
	grep -q -x 'User tor' /etc/tor/torrc
	VAR5=$?

	grep -q -x 'SocksPort 9050' /etc/tor/torrc
	VAR6=$?

	grep -q -x 'DNSPort 53' /etc/tor/torrc
	VAR7=$?

	grep -q -x 'TransPort 9040' /etc/tor/torrc
	VAR8=$?

	if [ $VAR5 -ne 0 ] || [ $VAR6 -ne 0 ] || [ $VAR7 -ne 0 ] || [ $VAR8 -ne 0 ]; then
		printf "${red}%s${endc} ${white}%s${white}\n" "[ FAILED ] To enable the transparent proxy add the following at the end of file:" "/etc/tor/torrc" >&2
		printf "${white}%s${endc}\n" "User tor"
		printf "${white}%s${endc}\n" "SocksPort 9050"
		printf "${white}%s${endc}\n" "DNSPort 53"
		printf "${white}%s${endc}\n" "TransPort 9040"
	exit 1
	fi
}


# Start transparent proxy
# ***********************
start_program () {
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

	# iptables settings:
	# ******************
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
	printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Configure system's DNS resolver to use Tor's DNSPort"
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
	
	# Tor Entry Guards
	#
	# delete file: "/var/lib/tor/state"
	# little explained:
	# when tor.service starting, a new file 'state' it's generated
	# when you connect to Tor network, a new Tor entry guards will be written on this file.
	printf "${blue}%s${endc} ${green}%s${endc}" "::" "Get fresh Tor entry guards? [Y/N]"
	read -p "${green}:${endc} " yn
	case $yn in
		[yY]|[y|Y] )
			rm -v /var/lib/tor/state
			printf "${green}%s${endc} ${white}%s${endc}\n" "[ OK ]" "When tor.service start, new Tor entry guards will obtained"
			;;
		*)
			;;
	esac

	# start tor.service
	printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Start Tor service... "
	systemctl start tor.service iptables
	sleep 6			
	printf "${green}%s${endc} ${white}%s${endc}\n" "[ OK ]" "Tor service is active"

	printf "${green}%s${endc} ${white}%s${endc}\n" "[ OK ]" "Transparent Proxy activated, your system is under Tor"
	printf "${blue}%s${endc} ${green}%s${endc}\n" "[ info ]" "use '--status' argument for check the program status"
}


# Stop transparent proxy 
# and return to clearnet
# **********************
stop () {
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
	#rm /etc/iptables/iptables.rules
	iptables-restore < /opt/iptables.backup
	printf "${green}%s${endc}\n" "Done"
	sleep 3

	# stop tor.service
	printf "${blue}%s${endc} ${green}%s${endc}" "::" "Stop Tor service... "
	systemctl stop tor.service
	printf "${green}%s${endc}\n" "Done"
	sleep 4

	# restore /etc/resolv.conf --> default nameserver 
	printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Restore '/etc/resolv.conf' file with default DNS"
	rm -v /etc/resolv.conf
	cp -vf /opt/resolv.conf.backup /etc/resolv.conf
	sleep 2

	# enable firewall ufw 
	enable_ufw
	printf "${green}%s${endc} ${white}%s${endc}\n" "[-]" "Transparent Proxy stopped"
}


# function for check public IP
check_ip () {
	printf "\n${blue}%s${endc} ${green}%s${endc}\n" "::" "Checking your public IP with curl, please wait..."
	
	local external_ip
	external_ip="$(curl -s -m 15 ipinfo.io)"	
	
	printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "IP Address Details:"
	printf "${white}%s%s${endc}\n\n" "$external_ip" | tr -d '"'
}


# check_status function
# *********************
# function for check status of program and services:
# check --> tor.service
# check --> public IP
# check --> dangerous open doors, execute --> netstat -tulpn
check_status () {
	check_root

	# check status of tor.service
	printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Check current status of Tor service"
	if systemctl is-active tor.service > /dev/null 2>&1; then
		printf "${green}%s${endc} ${white}%s${endc}\n" "[ OK ]" "Tor service is active"
	else
		printf "${red}%s${endc}\n" "[-] Tor service is not running! exiting..."
		exit 1
	fi

	# check current public IP
	check_ip

	# execute command "netstat -tulpn", check if there are dangerous open doors
	printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Check if there are open doors"
	printf "${blue}%s${endc} ${green}%s${endc} ${white}%s${endc}\n" "::" "run command: 'netstat -tulpn'"
	sleep 5 &
	netstat -tulpn | more
	printf "${white}%s${endc} ${green}%s${endc}\n" "[ NOTE ]" "For better network security, you must have only 'tor' on state: LISTEN"
	exit 0
}


# restart tor.service 
# and change IP
# *******************
restart () {
	check_root
	printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Restart Tor service and change IP"

	# systemctl stop/start service
	systemctl stop tor.service iptables
	sleep 3
	systemctl start tor.service iptables
	sleep 2
	
	printf "${green}%s${endc} ${white}%s${endc}\n" "[ OK ]" "Tor Exit Node changed"
	
	# check current public ip
    check_ip
}


# print nice "nerd" help menu'
help_menu () {
	banner
	
	printf "\n${white}%s${endc}\n\n" "Usage:"
	printf "${white}%s${endc} ${red}%s${endc} ${white}%s${endc} ${red}%s${endc}\n" "┌─╼" "$USER" "╺─╸" "$(hostname)"
	printf "${white}%s${endc} ${green}%s${endc}\n" "└───╼" "./$_PROGRAM --argument"

	printf "\n${white}%s${endc}\n\n" "Arguments available:"
	printf "${green}%s${endc}\n" "--help      show this help message and exit"
	printf "${green}%s${endc}\n" "--start     start transparent proxy through tor"
	printf "${green}%s${endc}\n" "--stop      reset iptables and return to clear navigation"
	printf "${green}%s${endc}\n" "--status    check status of program and services"
	printf "${green}%s${endc}\n" "--checkip   check only public IP"
	printf "${green}%s${endc}\n" "--restart   restart tor service and change IP"
	printf "${green}%s${endc}\n" "--version   display program and tor version then exit"
	exit 0
}


# cases user input
# ****************
case "$1" in
	--start)
		start_program
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

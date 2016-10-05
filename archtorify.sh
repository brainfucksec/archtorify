#!/bin/bash

# Program: archtorify.sh
# Version: 1.6.0 - 28/09/2016
# Operating System: Arch Linux
# Description: Transparent proxy trough Tor for Arch Linux
# Author: Brainfuck
# https://github.com/BrainfuckSec
# Dependencies: tor, wget

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
program="archtorify"
version="1.6.0"

# define colors
export red=$'\e[0;91m'
export green=$'\e[0;92m'
export blue=$'\e[0;94m'
export white=$'\e[0;97m'
export endc=$'\e[0m'


# banner
function banner {
printf "${white}
 _____         _   _           _ ___
|  _  |___ ___| |_| |_ ___ ___|_|  _|_ _
|     |  _|  _|   |  _| . |  _| |  _| | |
|__|__|_| |___|_|_|_| |___|_| |_|_| |_  |
                                    |___|

Transparent proxy trough Tor for Arch Linux

Version: $version
Author: Brainfuck${endc}\n"
}


# check if the program run as a root
function check_root {
	if [ "$(id -u)" -ne 0 ]; then
		printf "${red}%s${endc}\n" "[ failed ] Please run this program as a root!" >&2
		exit 1
	fi
}


# functions for firewall ufw
# check if ufw is installed and active, if not
# jump this function
function disable_ufw {
	if hash ufw 2>/dev/null; then
		if ufw status | grep -q active$; then
			printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Firewall ufw is active, disabling..."
			ufw disable > /dev/null 2>&1
			printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "ufw disabled"
			sleep 3
		else
			ufw status | grep -q inactive$;
			printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Firewall ufw is inactive, continue..."
		fi
	fi
}


# enable ufw 
# if ufw isn't installed, jump this function
function enable_ufw {
	if hash ufw 2>/dev/null; then
		if ufw status | grep -q inactive$; then
			printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Enabling firewall ufw"
			ufw enable > /dev/null 2>&1
			printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "ufw enabled"
			sleep 3
		fi
	fi
}


# check default configurations
# check if archtorify is properly configured
function check_default {
	# check dependencies (tor, wget)
	command -v tor > /dev/null 2>&1 ||
	{ printf >&2 "\n${red}%s${endc}\n" "[ failed ] tor isn't installed, exiting..."; exit 1; }

	command -v wget > /dev/null 2>&1 ||
	{ printf >&2 "\n${red}%s${endc}\n" "[ failed ] wget isn't installed, exiting..."; exit 1; }

	# check file /usr/lib/systemd/system/tor.service
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
		printf "\n${red}%s${endc}\n" "[ failed ] Please add this lines at /usr/lib/systemd/tor.service file:" >&2
		printf "${green}%s${endc}\n" "You can read the file 'tor.service-example' for an example of configuration" >&2
		printf "${white}%s${endc}\n" "[Service]"
		printf "${white}%s${endc}\n" "User=root"
		printf "${white}%s${endc}\n" "Group=root"
		printf "${white}%s${endc}\n" "Type=simple"
	exit 1
	fi

	# check owner and access rights of /var/lib/tor
	# ls -alh /var/lib/ | grep "tor"
	# output: drwx------  tor tor
	# (tor:tor chmod 755)
	if [ "$(stat -c '%U' /var/lib/tor)" != "tor" ] &&
		[ "$(stat -c '%a' /var/lib/tor)" != "755" ]; then
		printf "${red}%s${endc}\n" "[ failed ] Please give the right permissions and owner of /var/lib/tor folder"
		printf "${white}%s${endc}\n" "# chown -R tor:tor /var/lib/tor"
		printf "${white}%s${endc}\n" "# chmod -R 755 /var/lib/tor"
		printf "${white}%s${endc}\n" "# systemctl --system daemon-reload"
	exit 1
	fi

	# check file '/etc/tor/torrc'
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
		printf "${red}%s${endc}\n" "[ failed ] To enable the transparent proxy add the following at /etc/tor/torrc file:" >&2
		printf "${white}%s${endc}\n" "User tor"
		printf "${white}%s${endc}\n" "SocksPort 9050"
		printf "${white}%s${endc}\n" "DNSPort 53"
		printf "${white}%s${endc}\n" "TransPort 9040"
	exit 1
	fi
}


# start transparent proxy
# start program
function start {
	banner
	check_root
	check_default

	# check status of tor.service and stop it if is active
	if systemctl is-active tor.service > /dev/null 2>&1; then
		systemctl stop tor.service
	fi

	printf "\n${blue}%s${endc} ${green}%s${endc}\n" "::" "Starting Transparent Proxy"
	disable_ufw
	sleep 3

	# save iptables rules
	printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Backup iptables rules"
	iptables-save > /opt/iptables.backup
	sleep 2

	# flush current iptables
	printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Flush iptables rules"
	iptables -F
	iptables -t nat -F

	# configure system's DNS resolver to use Tor's DNSPort on the loopback interface
	printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Configure system's DNS resolver to use Tor's DNSPort"
	cp -vf /etc/resolv.conf /opt/resolv.conf.backup
	rm /etc/resolv.conf
	echo -e 'nameserver 127.0.0.1' > /etc/resolv.conf
	sleep 2

	# write new iptables rules on file /etc/iptables/iptables.rules
	printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Set new iptables rules"

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
--ipv6 -A OUTPUT -d ::1/8 -j ACCEPT
-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A OUTPUT -m owner --uid-owner "tor" -j ACCEPT
--ipv4 -A OUTPUT -j REJECT --reject-with icmp-port-unreachable
--ipv6 -A OUTPUT -j REJECT
COMMIT' >> /etc/iptables/iptables.rules
sleep 4

	# Tor Entry Guards
	# delete file: /var/lib/tor/state
	# when tor.service starting, a new file 'state' it's generated
	# when you connect to Tor network, a new Tor entry guards will be written
	# on this file.
	printf "${blue}%s${endc} ${green}%s${endc}" "::" "Get fresh Tor entry guards? [y/n]"
	read -p "${green}:${endc} " yn
	case $yn in
		[yY]|[y|Y] )
			rm -v /var/lib/tor/state
			printf "${blue}%s${endc} ${white}%s${endc}\n" "[ ok ]" "New Tor entry guards obtained"
			;;
		*)
			;;
	esac

	# start tor.service
	printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Start Tor service"
	systemctl start tor.service iptables
	sleep 6

	printf "${blue}%s${endc} ${white}%s${endc}\n" "[ ok ]" "Transparent Proxy activated, your system is under Tor"
	printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "use --status argument for check the program status"
}


# stop function
# stop transparent proxy and return to clearnet
function stop {
	check_root

	printf "\n${blue}%s${endc} ${green}%s${endc}\n"  "::" "Stopping Transparent Proxy"
	sleep 2

	# flush iptables
	printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Flush iptables rules"
	iptables -F
	iptables -t nat -F

	# restore iptables
	printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Restore the default iptables rules"
	rm /etc/iptables/iptables.rules
	iptables-restore < /opt/iptables.backup

	# stop tor.service
	printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Stop Tor service"
	systemctl stop tor.service
	sleep 4

	# restore /etc/resolv.conf --> default nameserver 
	printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Restore /etc/resolv.conf file with default DNS"
	rm -v /etc/resolv.conf
	cp -vf /opt/resolv.conf.backup /etc/resolv.conf
	sleep 2

	# enable firewall ufw 
	enable_ufw
	printf "${blue}%s${endc} ${white}%s${endc}\n" "[-]" "Transparent Proxy stopped"
}


# check_status function
# function for check status of program and services:
# tor.service, check public IP, netstat for open door
function check_status {
	check_root

	# check status of tor.service
	printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Check current status of Tor service"
	if systemctl is-active tor.service > /dev/null 2>&1; then
		printf "${blue}%s${endc} ${white}%s${endc}\n" "[ ok ]" "Tor service is active"
	else
		printf "${red}%s${endc}\n" "[-] Tor service is not running!"
		exit 1
	fi

	# check current public IP
	printf "\n${blue}%s${endc} ${green}%s${endc}\n" "::" "Checking your public IP, please wait..."
	local ext_ip
	ext_ip=$(wget -qO- ipinfo.io/ip)
	local city
	city=$(wget -qO- ipinfo.io/city)
	
	printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Current public IP:"
	printf "${white}%s%s${endc}\n\n" "$ext_ip - $city"

	# exec command "netstat -tulpn", check if there are open doors
	printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Check if there are open doors"
	printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "run command 'netstat -tulpn'"
	sleep 5 &
	netstat -tulpn
	exit 0
}


# restart tor.service and change IP
function restart {
	check_root
	printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Restart Tor service and change IP"

	# systemctl restart or stop/start service is the same?
	systemctl stop tor.service iptables
	sleep 3
	systemctl start tor.service iptables
	sleep 2
	# check tor.service after restart
	if systemctl is-active tor.service > /dev/null 2>&1; then
		printf "${blue}%s${endc} ${white}%s${endc}\n" "[ ok ]" "Tor service is active and your IP is changed"
		printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "use --status argument for check public IP"
	else
		printf "${red}%s${endc}\n" "[-] Tor service is not running!"
	fi
	sleep 4
}


# display program and tor version then exit
function print_version {
	printf "${white}%s${endc}\n" "$program version $version"
	printf "${white}%s${endc}\n" "$(tor --version)"
	exit 0
}


# print nice help message and exit
function help_menu {
	banner
	printf "\n${white}%s${endc}\n\n" "Usage:"
	printf "${white}%s${endc} ${red}%s${endc} ${white}%s${endc} ${red}%s${endc}\n" "┌─╼" "$USER" "╺─╸" "$(hostname)"
	printf "${white}%s${endc} ${green}%s${endc}\n" "└───╼" "./$program --argument"

	printf "\n${white}%s${endc}\n\n" "Arguments:"
	printf "${green}%s${endc}\n" "--help      show this help message and exit"
	printf "${green}%s${endc}\n" "--start     start transparent proxy for tor"
	printf "${green}%s${endc}\n" "--stop      reset iptables and return to clear navigation"
	printf "${green}%s${endc}\n" "--status    check status of program and services"
	printf "${green}%s${endc}\n" "--restart   restart tor service and change IP"
	printf "${green}%s${endc}\n" "--version   display program and tor version then exit"
	exit 0
}


# cases user input
case "$1" in
	--start)
		start
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

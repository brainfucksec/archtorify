#!/bin/bash

# Program: archtorify.sh
# Version: 1.5.1 - 24/08/2016
# Operative System: Arch Linux
# Description: Bash script for transparent proxy trought Tor
# Dev: Brainfuck
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
version="1.5.1"

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
                                             
Version: 1.5.1                        
Dev: Brainfuck${endc}\n"
}


# check if the program run as a root 
function check_root {
	if [ "$(id -u)" -ne 0 ]; then
		printf "${red}[!] Please run this program as a root!${endc}\n" >&2
		exit 1
	fi
}


# disable ufw (if is installed and active)
function disable_ufw {
	if ufw status | grep -q active$; then
		printf "${blue}::${endc} ${green}Firewall ufw is active, disabling...${endc}\n"
		ufw disable > /dev/null 2>&1
		printf "${blue}::${endc} ${green}ufw disabled${endc}\n"
		sleep 3
	else
		ufw status | grep -q inactive$;
		printf "${blue}::${endc} ${green}Firewall ufw is inactive, continue...${endc}\n"
	fi
}


# enable ufw 
function enable_ufw {
	if ufw status | grep -q inactive$; then
		printf "${blue}::${endc} ${green}Enabling firewall ufw${endc}\n"
		ufw enable > /dev/null 2>&1
		printf "${blue}::${endc} ${green}ufw enabled${endc}\n"
		sleep 3
	else
		printf "${blue}::${endc} ${green}Firewall ufw isn't installed, continue...${endc}\n"
	fi
}


# check current public IP 
function check_ip {
	local ext_ip=$(wget -qO- ipinfo.io/ip)
	local city=$(wget -qO- ipinfo.io/city)
	printf "${blue}::${endc} ${green}Current public IP:${endc}\n"
	printf "${white}%s%s${endc}\n" "$ext_ip - $city"
}


# check default configurations
function check_default {
	# tor is installed ?
	command -v tor > /dev/null 2>&1 ||
	{ printf "\n${red}[!] Tor isn't installed, exiting...${endc}\n"; exit 1; }

	# wget is installed ?
	command -v wget > /dev/null 2>&1 ||
	{ printf "\n${red}[!] wget isn't installed, exiting...${endc}\n"; exit 1; }

	# check file /usr/lib/systemd/system/tor.service
	# example config file: "tor.service-example"
	grep -q -x '\[Service\]' /usr/lib/systemd/system/tor.service
	VAR1=$?

	grep -q -x 'User=root' /usr/lib/systemd/system/tor.service
	VAR2=$?

	grep -q -x 'Group=root' /usr/lib/systemd/system/tor.service
	VAR3=$?
	
	grep -q -x 'Type=simple' /usr/lib/systemd/system/tor.service
	VAR4=$?

	if [ $VAR1 -ne 0 ] || [ $VAR2 -ne 0 ] || [ $VAR3 -ne 0 ] || [ $VAR4 -ne 0 ]; then
		printf "\n${red}[!]${endc} ${green}Please add this lines at /usr/lib/systemd/tor.service file:${endc}\n" >&2
		printf "${green}You can read 'tor.service-example' file for an example of configuration${endc}\n" >&2
		printf "${white}[Service]${endc}\n"
		printf "${white}User=root${endc}\n"
		printf "${white}Group=root${endc}\n"
		printf "${white}Type=simple${endc}\n"
	exit 1
	fi

	# check owner and access rights of /var/lib/tor
	# tor:tor
	# chmod 755 
	if [ "$(stat -c '%U' /var/lib/tor)" != "tor" ] && 
		[ "$(stat -c '%a' /var/lib/tor)" != "755" ]; then
		printf "${red}[!]${endc} ${green}Please give the right permissions and owner of /var/lib/tor folder${endc}\n"
		printf "${white}# chown -R tor:tor /var/lib/tor${endc}\n"
		printf "${white}# chmod -R 755 /var/lib/tor${endc}\n"
		printf "${white}# systemctl --system daemon-reload${endc}\n"
	exit 1
	fi

	# check file '/etc/tor/torrc'
	grep -q -x 'User tor' /etc/tor/torrc
	VAR5=$?

	grep -q -x 'SocksPort 9050' /etc/tor/torrc
	VAR6=$?

	grep -q -x 'DNSPort 53' /etc/tor/torrc
	VAR7=$?

	grep -q -x 'TransPort 9040' /etc/tor/torrc
	VAR8=$?

	if [ $VAR5 -ne 0 ] || [ $VAR6 -ne 0 ] || [ $VAR7 -ne 0 ] || [ $VAR8 -ne 0 ]; then
		printf "${red}[!]${endc} ${green}Please add this line at /etc/tor/torrc file${endc}\n"
		printf "${white}User tor${endc}\n"
		printf "${white}SocksPort 9050${endc}\n"
		printf "${white}DNSPort 53${endc}\n"
		printf "${white}TransPort 9040${endc}\n"
	exit 1
	fi
}


# if all configurations are ok, start the script
function start {
	banner
	check_root
	check_default

	# check status of tor.service and stop it if is active 
	if systemctl is-active tor.service > /dev/null 2>&1; then
		systemctl stop tor.service
	fi

	printf "\n${blue}::${endc} ${green}Starting Transparent Proxy${endc}\n"
	disable_ufw
	sleep 1

	# save iptables 
	printf "${blue}::${endc} ${green}Backup iptables rules${endc}\n"
	iptables-save > /opt/iptables.backup
	sleep 2 

	# flush iptables
	printf "${blue}::${endc} ${green}Flush iptables rules${endc}\n"
	iptables -F
	iptables -t nat -F

	# configure system's DNS resolver to use Tor's DNSPort on the loopback interface
	printf "${blue}::${endc} ${green}Configure system's DNS resolver to use Tor's DNSPort${endc}\n"
	cp /etc/resolv.conf /opt/resolv.conf.backup
	rm /etc/resolv.conf
	echo -e 'nameserver 127.0.0.1' > /etc/resolv.conf

	# write new iptables rules on file /etc/iptables/iptables.rules
	printf "${blue}::${endc} ${green}Set new iptables rules${endc}\n"

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

	# if you want, get fresh Tor entry guards by regenerating Tor state file
	# /var/lib/tor/state is deleted, it is created again at tor.service startup
	printf "${blue}::${endc} ${green}Get fresh Tor entry guards? [y/n]${endc}"
	read -p "${green}:${endc} " yn
	case $yn in
		[yY]|[y|Y] )
			rm /var/lib/tor/state
			printf "${blue}[+]${endc} ${white}New Tor entry guards obtained${endc}\n"
			;;
		*)
			;;
	esac
	
	# start tor.service 	
	printf "${blue}::${endc} ${green}Start Tor service${endc}\n"
	systemctl start tor.service iptables 
	sleep 6

	printf "${blue}[+]${endc} ${white}Transparent Proxy activated, your system is under Tor${endc}\n"
}


# stop transparent proxy and return to clearnet 
function stop {
	banner 
	check_root 

	printf "\n${blue}::${endc} ${green}Stopping Transparent Proxy${endc}\n"
	sleep 2

	# flush iptables
	printf "${blue}::${endc} ${green}Flush iptables rules${endc}\n"
	iptables -F
	iptables -t nat -F

	# restore iptables 
	printf "${blue}::${endc} ${green}Restore the default iptables rules${endc}\n"
	rm /etc/iptables/iptables.rules
	iptables-restore < /opt/iptables.backup

	# stop tor.service
	printf "${blue}::${endc} ${green}Stop Tor service${endc}\n"
	systemctl stop tor.service 
	sleep 4

	# restore /etc/resolv.conf --> default nameserver 
	printf "${blue}::${endc} ${green}Restore /etc/resolv.conf file with default DNS${endc}\n"
	rm /etc/resolv.conf
	cp /opt/resolv.conf.backup /etc/resolv.conf
	sleep 2

	# enable firewall ufw 
	enable_ufw
	printf "${blue}[-]${endc} ${white}Transparent Proxy stopped${endc}\n"
}


# check current status of tor.service 
function status {
	check_root	
	printf "${blue}::${endc} ${green}Check current status of Tor service${endc}\n"
	if systemctl is-active tor.service > /dev/null 2>&1; then
		printf "${blue}[+]${endc} ${white}Tor service is active${endc}\n"
	else		
		printf "${red}[!] Tor service is not running${endc}\n"
	fi
}


# restart tor.service and change IP
function restart {
	check_root
	printf "${blue}::${endc} ${green}Restart Tor service and change IP${endc}\n"
	systemctl restart tor.service iptables
	sleep 4
	check_ip
}


# display program and tor version then exit
function print_version {
	printf "${white}%s%s$program version $version${endc}\n"
	printf "${white}$(tor --version)${endc}\n"
	exit 0
}


# print help menu' 
function help_menu {
	banner	
	printf "\n${white}Usage:${endc}\n\n"
	printf "${white}┌─╼${endc} ${red}$USER${endc} $white╺─╸${endc} ${red}$(hostname)${endc}\n"
	printf "${white}└───╼${endc} ${green}./%s$program <--argument>${endc}\n"

	printf "\n${white}Arguments:${endc}\n\n"
	printf "${red}--help${endc}        ${green}show this help message and exit${endc}\n"
	printf "${red}--start${endc}       ${green}start transparent proxy for tor${endc}\n"
	printf "${red}--stop${endc}        ${green}reset iptables and return to clear navigation${endc}\n"
	printf "${red}--status${endc}      ${green}check program status${endc}\n"
	printf "${red}--restart${endc}     ${green}restart tor service and change IP${endc}\n"
	printf "${red}--checkip${endc}     ${green}print current public IP${endc}\n"
	printf "${red}--version${endc}     ${green}display program and tor version then exit${endc}\n"  
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
		status
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

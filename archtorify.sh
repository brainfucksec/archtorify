#!/bin/bash
						       							   						           	  
# Program: archtorify.sh                                       
#       													   	
# Version: 1.3 23/04/2016                              	   
# Operative System: Arch Linux  						       
# Dev: Brainfuck               		                       	          
# Description: Bash script for transparent proxy trought Tor                   			   
# Dependencies: Tor (pacman -S tor)			                   
							   
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


# define colors
export green='\e[0;92m'
export red='\e[0;91m'
export white='\e[0;97m'
export RESETCOLOR='\033[1;00m'


# banner
function banner {
cat << "EOF"
 _____         _   _           _ ___     
|  _  |___ ___| |_| |_ ___ ___|_|  _|_ _ 
|     |  _|  _|   |  _| . |  _| |  _| | |
|__|__|_| |___|_|_|_| |___|_| |_|_| |_  |
                                    |___|
V1.3
Dev: Brainfuck
https://www.github.com/BrainfuckSec
EOF
echo -e ""
}


# check if root run this script
function check_root {
	if [ "$(id -u)" -ne 0 ]; then
		echo -e "\n$red[!] Please run this script as a root!$RESETCOLOR\n" >&2
		exit 1
	fi
}


# disable ufw (if is installed and active)
function disable_ufw {
	if command -v ufw status > /dev/null 2>&1 &&
		ufw status | grep -q active$; then 
		echo -e "$white[info]$green Firewall ufw is active, disabling..$RESETCOLOR\n"
		ufw disable > /dev/null 2>&1
		echo -e "$white[info]$green ufw disabled$RESETCOLOR\n"
		sleep 3
	else
		echo -e "$white[info]$green Firewall ufw is inactive or not installed, continue..$RESETCOLOR\n"
	fi
}

# enable ufw
function enable_ufw {
	if command -v ufw status > /dev/null 2>&1 &&
		ufw status | grep -q inactive$; then
		echo -e "$white[info]$green Enabling firewall ufw$RESETCOLOR\n"
		ufw enable > /dev/null 2>&1
		echo -e "$white[info]$green ufw enabled$RESETCOLOR\n"
		sleep 3
	fi
}


# check current Tor node IP
function check_ip {
	csv=$(curl -A "Mozilla/5.0" -skLm 10 http://ip-api.com/json)
	public_ip=$(echo "$csv" | grep -oP "(?<=\"query\":\")[^\"]+")
	city=$(echo "$csv" | grep -oP "(?<=\"city\":\")[^\"]+" | tr [:lower:] [:upper:])
	country=$(echo "$csv" | grep -oP "(?<=\"country\":\")[^\"]+" | tr [:lower:] [:upper:])
	ISP=$(echo "$csv" | grep -oP "(?<=\"isp\":\")[^\"]+" | tr [:lower:] [:upper:])

	echo -e "===============================

IP  : $public_ip
City: $city - $country
ISP : $ISP

==============================="
}


# check default configurations 
function check_defaults {
	# check /usr/lib/systemd/system/tor.service
	grep -q -x '\[Service\]' /usr/lib/systemd/system/tor.service
	VAR1=$?
	
	grep -q -x 'User=root' /usr/lib/systemd/system/tor.service
	VAR2=$?
	
	grep -q -x 'Group=root' /usr/lib/systemd/system/tor.service
	VAR3=$?
	
	grep -q -x 'Type=simple' /usr/lib/systemd/system/tor.service
	VAR4=$?
	
	if [ $VAR1 -ne 0 ] || [ $VAR2 -ne 0 ] || [ $VAR3 -ne 0 ] || [ $VAR4 -ne 0 ]; then 
		echo -e "\n$red[!]$white Please add this lines at /usr/lib/systemd/system/tor.service file:\n"
		echo -e '[Service]'
		echo -e 'User=root'
		echo -e 'Group=root'
		echo -e 'Type=simple\n'
		echo -e "Then restart the script\n"
	exit 1
	fi
	
	# check owner and access rights of /var/lib/tor 
	if [ "$(stat -c '%U' /var/lib/tor)" != "tor" ] && [ "$(stat -c '%a' /var/lib/tor)" != "755" ]; then
		echo -e "\n$red[!]$white Please give the right permissions and owner of /var/lib/tor folder:\n"
		echo -e "# chown -R tor:tor /var/lib/tor\n"
		echo -e "# chmod -R 755 /var/lib/tor\n"
		echo -e "# systemctl --system daemon-reload\n"
		echo -e "Then restart the script\n"
	exit 1
	fi
		
	# check /etc/tor/torrc
	grep -q -x 'User tor' /etc/tor/torrc
	VAR5=$?
	
	grep -q -x 'SocksPort 9050' /etc/tor/torrc
	VAR6=$?
	
	grep -q -x 'DNSPort 5353' /etc/tor/torrc
	VAR7=$?
	
	grep -q -x 'TransPort 9040' /etc/tor/torrc
	VAR8=$?
	
	if [ $VAR5 -ne 0 ] || [ $VAR6 -ne 0 ] || [ $VAR7 -ne 0 ] || [ $VAR8 -ne 0 ]; then
		echo -e "\n$red[!]$white Please add this line at /etc/tor/torrc file:\n"
		echo -e 'User tor'
		echo -e 'SocksPort 9050'
		echo -e 'DNSPort 5353'
		echo -e 'TransPort 9040\n'
		echo -e "Then restart the script\n"
	exit 1
	fi
}


# the start function
function start {
	banner
	check_root
 
	# check if tor is installed
	command -v tor > /dev/null 2>&1 || 
	{ echo -e "\n$red[!] tor isn't installed, exiting...$RESETCOLOR"; exit 1; }
	
	check_defaults
	echo -e "$white[info]$green Starting Transparent Torification$RESETCOLOR\n"
	disable_ufw 

	# save iptables
	echo -e "$white[info]$green save iptables rules$RESETCOLOR\n"
	iptables-save > /opt/iptables.backup

	# flush iptables
	iptables -F
	iptables -t nat -F

	# save iptables file on /etc/iptables/iptables.rules
	echo -e "$white[info]$green set new iptables rules\n"

	echo '*nat
:PREROUTING ACCEPT [6:2126]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [17:6239]
:POSTROUTING ACCEPT [6:408]

-A PREROUTING ! -i lo -p udp -m udp --dport 53 -j REDIRECT --to-ports 5353
-A PREROUTING ! -i lo -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports 9040
-A OUTPUT -o lo -j RETURN
--ipv4 -A OUTPUT -d 192.168.0.0/16 -j RETURN
-A OUTPUT -m owner --uid-owner "tor" -j RETURN
-A OUTPUT -p udp -m udp --dport 53 -j REDIRECT --to-ports 5353
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
	
	# start tor.service
	systemctl start tor.service iptables

	echo -e "$white[+]$green Transparent Proxy activated, your system is under Tor$RESETCOLOR"
	sleep 3
}


# the stop function
function stop {
	check_root
	echo -e "\n$white[info]$green Stopping Transparent Proxy$RESETCOLOR\n"

	# stop tor.service - restore default iptables rules
	echo -e "$white[info]$green stop tor service and restore iptables rules$RESETCOLOR\n"
	iptables -F
	iptables -t nat -F

	rm /etc/iptables/iptables.rules
	iptables-restore < /opt/iptables.backup

	systemctl stop tor.service iptables
	sleep 4

	enable_ufw
	echo -e "$white[-]$green Transparent Proxy stopped$RESETCOLOR"
}


# restart tor and change ip 
function restart {
	check_root

	echo -e "$white[info]$green Restart Tor Service and change IP$RESETCOLOR\n"
	systemctl restart tor.service iptables
	sleep 4
	check_ip
}


# cases (start stop restart checkip)
case "$1" in
	start)
		start
	;;
	stop)
		stop
	;;
	restart)
		restart
	;;
	checkip)
		check_ip
	;;
   *)


# program usage 
banner
echo -e "\n$white USAGE:

┌─╼ $red$USER$white ╺─╸ $red$(hostname)$white
└───╼ $green""./archtorify.sh $white[ $green""start$white | $green""stop$white | $green""restart$white | $green""checkip $white""]

$red start$white -$green Start Transparent Proxy for Tor

$red stop$white -$green Reset iptables and return to clear navigation

$red restart$white -$green Restart Tor Service and change IP

$red checkip$white -$green Print current Tor node IP
$RESETCOLOR" >&2 
exit 1
;;
esac
echo -e $RESETCOLOR

exit 0 

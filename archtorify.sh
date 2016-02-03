#!/bin/bash
						       							   						           	  
# Program: archtorify.sh                                       
#       													   	
# Version: 1.2  [1/12/2015]                              	   
# Operative System: Arch Linux  						       
# Dev: Brainfuck               		                       	          
# Description: Bash script for transparent proxy trought Tor                   			   
# Dependencies: Tor (pacman -S tor)			                   
#                                               			                
							   
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



# colors 
export GREEN='\033[1;92m'
export RED='\033[1;91m'
export WHITE='\033[1;97m'
export RESETCOLOR='\033[1;00m'


# bannner
function banner {
cat << "EOF"
 _____         _   _           _ ___     
|  _  |___ ___| |_| |_ ___ ___|_|  _|_ _ 
|     |  _|  _|   |  _| . |  _| |  _| | |
|__|__|_| |___|_|_|_| |___|_| |_|_| |_  |
                                    |___|

V1.2
EOF
}


# check if root run this script
function checkroot {
	if [ "$(id -u)" -ne 0 ]; then
		echo -e "\n$RED[!] Please run this script as a root!$RESETCOLOR\n" >&2
		exit 1
	fi
}


# check defaults file configuration 
function checkdefaults {
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
		echo -e "\n$RED[!] $WHITE Please add this lines at /usr/lib/systemd/system/tor.service file:\n"
		echo -e "==========="
		echo -e '[Service]'
		echo -e 'User=root'
		echo -e 'Group=root'
		echo -e 'Type=simple'
		echo -e "===========\n"
		echo -e "then restart the script"
	exit 1
	fi
	
	# check owner and access rights of /var/lib/tor 
	if [ "$(stat -c '%U' /var/lib/tor)" != "tor" ] && [ "$(stat -c '%a' /var/lib/tor)" != "755" ]; then
		echo -e "\n$RED[!] $WHITE Please give the right permissions and owner of /var/lib/tor folder:\n"
		echo -e "# chown -R tor:tor /var/lib/tor\n"
		echo -e "# chmod -R 755 /var/lib/tor\n"
		echo -e "# systemctl --system daemon-reload\n"
		echo -e "then restart the script"
		sleep 6
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
		echo -e "\n$RED[!] $WHITE Please add this line at /etc/tor/torrc file:\n"
		echo -e "=============="
		echo -e 'User tor'
		echo -e 'SocksPort 9050'
		echo -e 'DNSPort 5353'
		echo -e 'TransPort 9040'
		echo -e "=============="
		echo -e "then restart the script"
	exit 1
	fi
}


# the start function
function start {
	checkroot
	checkdefaults
	banner
	echo -e "\n$WHITE[info] $GREEN Starting Transparent Torification$RESETCOLOR\n"	

	# save iptables 
	echo -e "$WHITE[info] $GREEN save iptables rules$RESETCOLOR\n"
	iptables-save > /opt/iptables.backup
	
	# flush iptables
	iptables -F
	iptables -t nat -F	
	
	# save iptables file on /etc/iptables/iptables.rules
	echo -e "$WHITE[info] $GREEN set iptables for Transparent Torifing\n"
	
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
	
	echo -e "$WHITE[$GREEN Transparent Proxy activaded, your system is under Tor $WHITE]$RESETCOLOR"
	sleep 3
}


# the stop function
function stop {
	checkroot 	
	echo -e "\n$WHITE[info] $GREEN Stopping Transparent Proxy$RESETCOLOR\n"
	
	# restore iptables
	echo -e "$WHITE[info] $GREEN stop tor service and restore iptables rules$RESETCOLOR\n"
	iptables -F
	iptables -t nat -F
	
	rm /etc/iptables/iptables.rules
	iptables-restore < /opt/iptables.backup
	
	systemctl stop tor.service iptables
	sleep 4	
	
	echo -e "$WHITE[$GREEN Transparent Proxy stopped $WHITE]$RESETCOLOR"	
}


# restart if you want to change ip 
function restart {
	checkroot	
	systemctl restart tor.service iptables 
	sleep 4
	echo -e "$WHITE[info] $GREEN Restart Tor Service and change IP$RESETCOLOR\n"
	sleep 1
}


# case (start stop restart)
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
   *)


# usage
echo -e "\n$GREEN[Archtorify v1.2]-[Usage]

╭─[$RED$USER$GREEN]-[$RED`hostname`$GREEN]
╰──> $WHITE""./archtorify.sh $GREEN[$WHITE""start$GREEN | $WHITE""stop$GREEN | $WHITE""restart$GREEN""]

$RED start$GREEN -$WHITE Start Transparent Proxy for Tor

$RED stop$GREEN -$WHITE Reset iptables and return to clear navigation

$RED restart$GREEN -$WHITE Restart Tor Service and change IP

$RESETCOLOR" >&2 
exit 1
;;
esac

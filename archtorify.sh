#!/usr/bin/env bash

# archtorify.sh
#
# Arch Linux - Transparent proxy through Tor
#
# Copyright (C) 2015-2018 Brainfuck

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


# Program information
readonly prog_name="archtorify"
readonly version="1.15.0"
readonly author="Brainfuck"
readonly git_url="https://github.com/brainfucksec/archtorify"

# URL for BUG reports :)
report_url="https://github.com/brainfucksec/archtorify/issues"

# Define colors for terminal output
export red=$'\e[0;91m'
export green=$'\e[0;92m'
export blue=$'\e[0;94m'
export white=$'\e[0;97m'
export cyan=$'\e[0;96m'
export endc=$'\e[0m'

# Set program directories and files
# configuration files: /usr/share/archtorify/data
# backup files: /opt/archtorify/backups
readonly config_dir="/usr/share/archtorify/data"
readonly backup_dir="/opt/archtorify/backups"


# Show program banner
#####################
banner() {
printf "${white}
-----------------------------------------
-----------------------------------------

 _____         _   _           _ ___
|  _  |___ ___| |_| |_ ___ ___|_|  _|_ _
|     |  _|  _|   |  _| . |  _| |  _| | |
|__|__|_| |___|_|_|_| |___|_| |_|_| |_  |
                                    |___|

-----------------------------------------
-----------------------------------------

Version: $version
Author: $author
$git_url${endc}\\n"
}


# Check if the program run as a root
####################################
check_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        printf "\\n${red}%s${endc}\\n" \
               "[ failed ] Please run this program as a root!" 2>&1
        exit 1
    fi
}


# Display program and Tor version
#################################
print_version() {
    printf "${white}%s${endc}\\n" "$prog_name version $version"
    printf "${white}%s${endc}\\n" "$(tor --version)"
    exit 0
}


# ufw firewall functions (running only if ufw exist)
#
# Disable ufw:
##############
# If ufw is installed and/or active disable it, if isn't installed,
# do nothing, don't display nothing to user, just jump to next function
disable_ufw() {
    if hash ufw 2>/dev/null; then
        if ufw status | grep -q active$; then
            printf "${blue}%s${endc} ${green}%s${endc}\\n" \
                   "::" "Firewall ufw is active, disabling..."
            ufw disable
        else
            ufw status | grep -q inactive$;
            printf "${blue}%s${endc} ${green}%s${endc}\\n" \
                   "::" "Firewall ufw is inactive, continue..."
        fi
    fi
}


# Enable ufw:
#############
# Often, if ufw isn't installed, again, do nothing
# and jump to the next function
enable_ufw() {
    if hash ufw 2>/dev/null; then
        if ufw status | grep -q inactive$; then
            printf "\\n${blue}%s${endc} ${green}%s${endc}\\n" \
                   "::" "Enabling firewall ufw..."
            ufw enable
        fi
    fi
}


# Setup program files
#####################
# Function for replace default system files with program files
replace_file() {
    local source_file="$1"
    local dest_file="$2"

    # Backup original file in the backup directory
    if ! cp -vf "$1" "$backup_dir/$2.backup" 2>/dev/null; then
        printf "\\n${red}%s${endc}\\n" \
            "[ failed ] can't copy original '$1' file in the backup directory."

        printf "${red}%s${endc}\\n" "Please report bugs at: $report_url"
        exit 1
    fi

    # Copy new file with new settings
    if ! cp -vf "$config_dir/$2" "$1" 2>/dev/null; then
        printf "\\n${red}%s${endc}\\n" \
               "[ failed ] can't set '$1'"

        printf "${red}%s${endc}\\n" "Please report bugs at: $report_url"
        exit 1
    fi
}


# Check default settings:
#########################
check_defaults() {
    # Check dependencies (tor)
    if ! hash tor 2>/dev/null; then
        printf "\\n${red}%s${endc}\\n" \
               "[ failed ] '$package' isn't installed, exit"
        exit 1
    fi

    # Check if program's directories exist
    # bash `-d`: test if the given directory exists or not.
    if [ ! -d "$backup_dir" ]; then
        printf "\\n${red}%s${endc}\\n" \
               "[ failed ] directory '$backup_dir' not exist, run makefile first!"
        exit 1
    fi

    if [ ! -d "$config_dir" ]; then
        printf "\\n${red}%s${endc}\\n" \
               "[ failed ] directory '$config_dir' not exist, run makefile first!"
        exit 1
    fi

    # Check file: `/usr/lib/systemd/system/tor.service`
    # source: https://wiki.archlinux.org/index.php/tor#Transparent_Torification
    # reference file: `/usr/share/archtorify/data/tor.service`
    grep -q -x '\[Service\]' /usr/lib/systemd/system/tor.service
    VAR1=$?

    grep -q -x 'User=root' /usr/lib/systemd/system/tor.service
    VAR2=$?

    grep -q -x 'Group=root' /usr/lib/systemd/system/tor.service
    VAR3=$?

    grep -q -x 'Type=simple' /usr/lib/systemd/system/tor.service
    VAR4=$?

    # and replace original `tor.service` file if needed
    if [[ $VAR1 -ne 0 ]] || [[ $VAR2 -ne 0 ]] || [[ $VAR3 -ne 0 ]] || [[ $VAR4 -ne 0 ]]; then
        printf "\\n${blue}%s${endc} ${green}%s${endc}\\n" \
               "::" "Setting file: /usr/lib/systemd/system/tor.service"

        replace_file /usr/lib/systemd/system/tor.service tor.service
    fi

    # Check permissions of directory: `/var/lib/tor`
    # correct permissions: drwx------  tor tor
    # numerical value: 755
    if [[ "$(stat -c '%U' /var/lib/tor)" != "tor" ]] &&
        [[ "$(stat -c '%a' /var/lib/tor)" != "755" ]]; then
        printf "\\n${blue}%s${endc} ${green}%s${endc}\\n" \
               "::" "Setting permissions of directory: /var/lib/tor"

        # Exec commands
        # Set owner `tor`
        chown -R tor:tor /var/lib/tor

        # chmod 755
        chmod -R 755 /var/lib/tor

        # reload systemd daemons
        systemctl --system daemon-reload

        printf "%s\\n" "... Done"
    fi

    # Check file: `/etc/tor/torrc`
    # reference file: `/usr/share/archtorify/data/torrc`
    # grep required strings from existing file
    grep -q -x 'User tor' /etc/tor/torrc
    VAR5=$?

    grep -q -x 'SocksPort 9050' /etc/tor/torrc
    VAR6=$?

    grep -q -x 'DNSPort 53' /etc/tor/torrc
    VAR7=$?

    grep -q -x 'TransPort 9040' /etc/tor/torrc
    VAR8=$?

    # and replace original `/etc/tor/torrc` file if needed
    if [ $VAR5 -ne 0 ] || [ $VAR6 -ne 0 ] || [ $VAR7 -ne 0 ] || [ $VAR8 -ne 0 ]; then
        printf "\\n${blue}%s${endc} ${green}%s${endc}\n" "::" \
               "Setting file: /etc/tor/torrc"

        replace_file /etc/tor/torrc torrc
    fi
}


# Start transparent proxy
#########################
main() {
    banner
    sleep 1
    check_root
    check_defaults

    # Check status of tor.service and stop it if is active (for better security)
    if systemctl is-active tor.service >/dev/null 2>&1; then
        systemctl stop tor.service
    fi

    printf "\\n${cyan}%s${endc} ${green}%s${endc}\\n" \
           "==>" "Starting Transparent Proxy"
    sleep 2
    disable_ufw

    # iptables settings:
    # Save current iptables rules
    printf "\\n${blue}%s${endc} ${green}%s${endc}" "::" "Backup iptables rules... "
    iptables-save > "$backup_dir/iptables.backup"
    printf "%s\\n" "Done"

    # Flush current iptables rules
    printf "${blue}%s${endc} ${green}%s${endc}" "::" "Flush iptables rules... "
    iptables -F
    iptables -t nat -F
    printf "%s\\n" "Done"

    # Configure system's DNS resolver to use Tor's DNSPort
    # on the loopback interface, i.e. write nameserver 127.0.0.1
    # to `etc/resolv.conf` file
    printf "\\n${blue}%s${endc} ${green}%s${endc}\\n" \
           "::" "Configure system's DNS resolver to use Tor's DNSPort"

    if ! cp -vf /etc/resolv.conf "$backup_dir/resolv.conf.backup" 2>/dev/null; then
        printf "\\n${red}%s${endc}\\n" \
               "[ failed ] can't copy resolv.conf to the backup directory"

        printf "${red}%s${endc}\\n" "Please report bugs at: $report_url"
        exit 1
    fi

    printf "%s\\n" "nameserver 127.0.0.1" > /etc/resolv.conf
    sleep 1

    # Write new iptables rules on file: `/etc/iptables/iptables.rules`
    # source: https://wiki.archlinux.org/index.php/Tor#Transparent_Torification
    # reference file: `/usr/share/archtorify/data/iptables.rules`
    printf "\\n${blue}%s${endc} ${green}%s${endc}\\n" "::" "Set new iptables rules... "

    if ! cp -vf "$config_dir/iptables.rules" /etc/iptables/iptables.rules 2>/dev/null; then
        printf "\\n${red}%s${endc}\\n" \
               "[ failed ] can't set '/etc/iptables/iptables.rules'"

        printf "${red}%s${endc}\\n" "Please report bugs at: $report_url"
        exit 1
    fi

    # Start tor.service with new configuration
    printf "\\n${blue}%s${endc} ${green}%s${endc}\\n" "::" "Start Tor service"
    if ! systemctl start tor.service iptables 2>/dev/null; then
        printf "\\n${red}%s${endc}\\n" "[ failed ] systemd error, exit!"
        exit 1
    fi

    # check program status
    check_status

    printf "${cyan}%s${endc} ${green}%s${endc}\\n" \
           "[ ok ]" "Transparent Proxy activated, your system is under Tor"
}


# Stop transparent proxy
########################
stop() {
    check_root

    printf "${cyan}%s${endc} ${green}%s${endc}\\n" \
           "==>" "Stopping Transparent Proxy"
    sleep 2

    # Resets default settings
    #
    # Flush current iptables rules
    printf "${blue}%s${endc} ${green}%s${endc}" "::" "Flush iptables rules... "
    iptables -F
    iptables -t nat -F
    printf "%s\\n" "Done"

    # Restore iptables
    printf "${blue}%s${endc} ${green}%s${endc}" \
           "::" "Restore the default iptables rules... "

    rm /etc/iptables/iptables.rules

    iptables-restore < "$backup_dir/iptables.backup"
    printf "%s\\n" "Done"

    # Stop tor.service
    printf "${blue}%s${endc} ${green}%s${endc}" "::" "Stop Tor service... "

    systemctl stop tor.service
    printf "%s\\n" "Done"

    # Restore `/etc/resolv.conf` --> default nameserver
    printf "\\n${blue}%s${endc} ${green}%s${endc}\\n" \
           "::" "Restore '/etc/resolv.conf' file with default DNS"

    # delete current `/etc/resolv.conf` file
    rm -v /etc/resolv.conf

    # Restore default `/etc/resolv.conf`
    #
    # if operating system use `resolvconf` restore file with it,
    # otherwise copy the original file from backup directory
    if hash resolvconf 2>/dev/null; then
        resolvconf -u
    else
        cp -vf "$backup_dir/resolv.conf.backup" /etc/resolv.conf
    fi

    # Restore default `/etc/tor/torrc` file
    printf "\\n${blue}%s${endc} ${green}%s${endc}\\n" \
           "::" "Restore default '/etc/tor/torrc' file"

    cp -vf "$backup_dir/torrc.backup" /etc/tor/torrc

    # Restore default `/usr/lib/systemd/system/tor.service` file
    printf "\\n${blue}%s${endc} ${green}%s${endc}\\n" \
           "::" "Restore default '/usr/lib/systemd/system/tor.service' file"

    cp -vf "$backup_dir/tor.service.backup" /usr/lib/systemd/system/tor.service

    # Enable firewall ufw
    enable_ufw

    ## End
    printf "\\n${cyan}%s${endc} ${green}%s${endc}\\n" \
           "[-]" "Transparent Proxy stopped"
}


# Check public IP
#################
check_ip() {
    check_root

    printf "${cyan}%s${endc} ${green}%s${endc}\\n" \
           "==>" "Checking your public IP, please wait..."

    # curl request: http://ipinfo.io/geo
    # TODO: add a better error handling
    if ! external_ip="$(curl -s -m 10 ipinfo.io/geo)"; then
        printf "${red}%s${endc}\\n" "[ failed ] curl: HTTP request error!"
        printf "${red}%s${endc}\\n" "Please check your network settings."
        exit 1
    fi

    # Print output
    printf "${blue}%s${endc} ${green}%s${endc}\\n" "::" "IP Address Details:"
    printf "${white}%s${endc}\\n" "$external_ip" | tr -d '"{}' | sed 's/ //g'
}


# Check status of program and services:
#######################################
#
# check --> tor.service
# check --> tor settings
# check --> public IP
check_status () {
    check_root

    # Check status of tor.service
    printf "${cyan}%s${endc} ${green}%s${endc}\\n" \
           "==>" "Check current status of Tor service"

    if systemctl is-active tor.service >/dev/null 2>&1; then
        printf "${cyan}%s${endc} ${green}%s${endc}\\n\\n" \
               "[ ok ]" "Tor service is active"
    else
        printf "${red}%s${endc}\\n" "[-] Tor service is not running! exiting..."
        exit 1
    fi

    # Check tor network settings
    # make http request with curl at: https://check.torproject.org/
    # and grep the necessary strings from the html page to test connection
    # with tor
    printf "${cyan}%s${endc} ${green}%s${endc}\\n" \
           "==>" "Check Tor network settings"

    local host_port="localhost:9050"
    local url="https://check.torproject.org/"

    # curl: `-L` and `tac` for avoid error: (23) Failed writing body
    # https://github.com/kubernetes/helm/issues/2802
    # https://stackoverflow.com/questions/16703647/why-curl-return-and-error-23-failed-writing-body
    if curl -m 15 --socks5 "$host_port" --socks5-hostname "$host_port" -sL "$url" \
        | cat | tac | grep -q 'Congratulations'; then
        printf "${cyan}%s${endc} ${green}%s${endc}\\n\\n" \
               "[ ok ]" "Your system is configured to use Tor"
    else
        printf "${red}%s${endc}\\n\\n" "Your system is not using Tor"
        exit 1
    fi

    # Check current public IP
    check_ip
}


# Restart tor.service and change IP
###################################
restart() {
    check_root

    printf "${cyan}%s${endc} ${green}%s${endc}\\n" \
            "==>" "Restart Tor service and change IP"

    systemctl restart tor.service iptables
    sleep 3

    printf "${cyan}%s${endc} ${green}%s${endc}\\n\\n" \
           "[ ok ]" "Tor Exit Node changed"

    # Check current public ip
    check_ip
    exit 0
}


# Print help menù
#################
usage() {
    printf "${white}%s${endc}\\n" "$prog_name $version"

    printf "${white}%s${endc}\\n\\n" "Arch Linux - Transparent proxy through Tor"

    printf "${green}%s${endc}\\n\\n" "Usage:"

    printf "${white}%s${endc} ${red}%s${endc} ${white}%s${endc} ${red}%s${endc}\\n" \
           "┌─╼" "$USER" "╺─╸" "$(hostname)"
    printf "${white}%s${endc} ${green}%s${endc}\\n\\n" "└───╼" "$prog_name [option]"

    printf "${green}%s${endc}\\n\\n" "Options:"

    printf "${white}%s${endc}\\n" \
           "-h, --help      show this help message and exit"

    printf "${white}%s${endc}\\n" \
           "-t, --tor       start transparent proxy through tor"

    printf "${white}%s${endc}\\n" \
           "-c, --clearnet  reset iptables and return to clear navigation"

    printf "${white}%s${endc}\\n" \
           "-s, --status    check status of program and services"

    printf "${white}%s${endc}\\n" \
           "-i, --ipinfo    check only public IP"

    printf "${white}%s${endc}\\n" \
           "-r, --restart   restart tor service and change IP"

    printf "${white}%s${endc}\\n" \
           "-v, --version   display program and tor version then exit"
    exit 0
}


# Parse command line options
############################
if [ "$#" == 0 ]; then
    printf "%s\\n" "$prog_name: Argument required"
    printf "%s\\n" "Try '$prog_name --help' for more information."
    exit 1
fi

while [ "$#" -gt 0 ]; do

    case "$1" in
        -t | --tor)
            main
            shift
            ;;
        -c | --clearnet)
            stop
            ;;
        -r | --restart)
            restart
            ;;
        -s | --status)
            check_status
            ;;
        -i | --ipinfo)
            check_ip
            ;;
        -v | --version)
            print_version
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        -- | -* | *)
            printf "%s\\n" "$prog_name: Invalid option '$1'"
            printf "%s\\n" "Try '$prog_name --help' for more information."
            exit 1
            ;;
    esac
    shift
done

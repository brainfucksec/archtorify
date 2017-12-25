#!/usr/bin/env bash

# Program: archtorify.sh
# Version: 1.11.0
# Operating System: Arch Linux
# Description: Transparent proxy through Tor
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
readonly program="archtorify"
readonly version="1.11.0"
readonly author="Brainfuck"
readonly git_url="https://github.com/brainfucksec/archtorify"

# Define colors for terminal output
export red=$'\e[0;91m'
export green=$'\e[0;92m'
export blue=$'\e[0;94m'
export white=$'\e[0;97m'
export cyan=$'\e[0;96m'
export endc=$'\e[0m'

## Set program's directories and files
# configuration files: /usr/share/archtorify/data
# backup files: /opt/archtorify/backups
readonly config_dir="/usr/share/archtorify/data"
readonly backup_dir="/opt/archtorify/backups"


# Show program banner
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

Version: $version
Author: $author
$git_url${endc}\\n"
}


# Check if the program run as a root
check_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        printf "\\n${red}%s${endc}\\n" \
            "[ failed ] Please run this program as a root!" 2>&-
        exit 1
    fi
}


# Display program and Tor version then exit
print_version() {
    printf "${white}%s${endc}\\n" "$program version $version"
    printf "${white}%s${endc}\\n" "$(tor --version)"
    exit 0
}


## Functions for firewall ufw (launched only if ufw exist)
# Disable ufw:
# If ufw is installed and/or active disable it, if isn't installed,
# do nothing, don't display nothing to user, just jump to next function
disable_ufw() {
    if hash ufw 2>/dev/null; then
        if ufw status | grep -q active$; then
            printf "${blue}%s${endc} ${green}%s${endc}\\n" \
                "::" "Firewall ufw is active, disabling..."
            ufw disable
            sleep 3
        else
            ufw status | grep -q inactive$;
            printf "${blue}%s${endc} ${green}%s${endc}\\n" \
                "::" "Firewall ufw is inactive, continue..."
        fi
    fi
}


# Enable ufw:
# Often, if ufw isn't installed, again, do nothing and jump to the next function
enable_ufw() {
    if hash ufw 2>/dev/null; then
        if ufw status | grep -q inactive$; then
            printf "${blue}%s${endc} ${green}%s${endc}\\n" \
                "::" "Enabling firewall ufw..."
            ufw enable
            sleep 3
        fi
    fi
}


## Check default configurations
# Check if archtorify is properly configured, begin ...
check_defaults() {
    # Check dependencies (tor)
    declare -a dependencies=("tor");
    for package in "${dependencies[@]}"; do
        if ! hash "$package" 2>/dev/null; then
            printf "\\n${red}%s${endc}\\n" \
                "[ failed ] '$package' isn't installed, exit";
            exit 1
        fi
    done

    ## Check if program's directories exist
    # bash "-d": test if the given directory exists or not.
    if [ ! -d "$backup_dir" ]; then
        printf "\\n${red}%s${endc}\\n" \
            "[ failed ] directory '$backup_dir' not exist, run makefile first!";
        exit 1
    fi

    if [ ! -d "$config_dir" ]; then
        printf "\\n${red}%s${endc}\\n" \
            "[ failed ] directory '$config_dir' not exist, run makefile first!";
        exit 1
    fi

    ## Check file: "/usr/lib/systemd/system/tor.service"
    # reference: https://wiki.archlinux.org/index.php/tor#Transparent_Torification
    # reference file: "/usr/share/archtorify/data/tor.service"
    grep -q -x '\[Service\]' /usr/lib/systemd/system/tor.service
    VAR1=$?

    grep -q -x 'User=root' /usr/lib/systemd/system/tor.service
    VAR2=$?

    grep -q -x 'Group=root' /usr/lib/systemd/system/tor.service
    VAR3=$?

    grep -q -x 'Type=simple' /usr/lib/systemd/system/tor.service
    VAR4=$?

    # If this file isn't already configured, configure it now
    if [[ $VAR1 -ne 0 ]] || [[ $VAR2 -ne 0 ]] || [[ $VAR3 -ne 0 ]] || [[ $VAR4 -ne 0 ]]; then
        printf "\\n${blue}%s${endc} ${green}%s${endc}\\n" \
            "::" "Setting file: /usr/lib/systemd/system/tor.service"

        # Backup original "tor.service" file to the backup directory
        if ! cp -vf /usr/lib/systemd/system/tor.service "$backup_dir/tor.service.backup"; then
            printf "\\n${red}%s${endc}\\n" \
                "[ failed ] can't copy original 'tor.service' file to the backup directory."
            printf "${red}%s${endc}\\n" \
                "Please report bugs at: https://github.com/brainfucksec/archtorify/issues"
            exit 1
        fi

        # Copy new "tor.service" file with new settings
        if ! cp -vf "$config_dir/tor.service" /usr/lib/systemd/system/tor.service; then
            printf "\\n${red}%s${endc}\\n" \
                "[ failed ] can't set '/usr/lib/systemd/system/tor.service'"
            printf "${red}%s${endc}\\n" \
                "Please report bugs at: https://github.com/brainfucksec/archtorify/issues"
            exit 1
        fi
    fi

    ## Check permissions of directory: "/var/lib/tor"
    # correct permissions: drwx------  tor tor
    # "755"
    if [[ "$(stat -c '%U' /var/lib/tor)" != "tor" ]] &&
        [[ "$(stat -c '%a' /var/lib/tor)" != "755" ]]; then
        printf "${blue}%s${endc} ${green}%s${endc}\\n" \
            "::" "Setting permissions of directory: /var/lib/tor"

        ## Exec commands
        # Set owner "tor"
        chown -R tor:tor /var/lib/tor
        sleep 1
        # chmod 755
        chmod -R 755 /var/lib/tor
        sleep 1
        # reload systemd daemons
        systemctl --system daemon-reload

        printf "${white}%s${endc}\\n" "... Done"
    fi

    # Check file: "/etc/tor/torrc"
    # reference file: "/usr/share/archtorify/data/torrc"
    grep -q -x 'User tor' /etc/tor/torrc
    VAR5=$?

    grep -q -x 'SocksPort 9050' /etc/tor/torrc
    VAR6=$?

    grep -q -x 'DNSPort 53' /etc/tor/torrc
    VAR7=$?

    grep -q -x 'TransPort 9040' /etc/tor/torrc
    VAR8=$?

    # If this file is not configured, configure it now
    if [ $VAR5 -ne 0 ] || [ $VAR6 -ne 0 ] || [ $VAR7 -ne 0 ] || [ $VAR8 -ne 0 ]; then
        printf "\\n${blue}%s${endc} ${green}%s${endc}\n" "::" "Setting file: /etc/tor/torrc"

        # Backup original tor "torrc" file to the backup directory
        if ! cp -vf /etc/tor/torrc "$backup_dir/torrc.backup"; then
            printf "\\n${red}%s${endc}\\n" \
                "[ failed ] can't copy original tor 'torrc' file to the backup directory"
            printf "${red}%s${endc}\\n" \
                "Please report bugs at: https://github.com/brainfucksec/archtorify/issues"
            exit 1
        fi

        # Copy new "torrc" file with settings for archtorify
        if ! cp -vf "$config_dir/torrc" /etc/tor/torrc; then
            printf "\\n${red}%s${endc}\\n" \
                "[ failed ] can't set '/etc/tor/torrc'"
            printf "${red}%s${endc}\\n" \
                "Please report bugs at: https://github.com/brainfucksec/archtorify/issues"
            exit 1
        fi
    fi
}


# Start transparent proxy
main() {
    banner
    check_root
    check_defaults

    # Check status of tor.service and stop it if is active (for better security)
    if systemctl is-active tor.service >/dev/null 2>&1; then
        systemctl stop tor.service
    fi

    printf "\\n${cyan}%s${endc} ${green}%s${endc}\\n" "==>" "Starting Transparent Proxy"
    disable_ufw
    sleep 3

    ## Begin iptables settings:
    # Save current iptables rules
    printf "${blue}%s${endc} ${green}%s${endc}" "::" "Backup iptables rules... "

    if ! iptables-save > "$backup_dir/iptables.backup"; then
        printf "\\n${red}%s${endc}\\n" \
            "[ failed ] can't copy iptables rules to the backup directory"
        exit 1
    fi

    printf "${white}%s${endc}\\n" "Done"
    sleep 2

    # Flush current iptables rules
    printf "${blue}%s${endc} ${green}%s${endc}" "::" "Flush iptables rules... "
    iptables -F
    iptables -t nat -F
    printf "${white}%s${endc}\\n" "Done"

    # Configure system's DNS resolver to use Tor's DNSPort on the loopback interface
    # i.e. write nameserver 127.0.0.1 to "etc/resolv.conf" file
    printf "${blue}%s${endc} ${green}%s${endc}\\n" \
        "::" "Configure system's DNS resolver to use Tor's DNSPort"

    if ! cp -vf /etc/resolv.conf "$backup_dir/resolv.conf.backup"; then
        printf "\\n${red}%s${endc}\\n" \
            "[ failed ] can't copy resolv.conf to the backup directory"
        exit 1
    fi

    printf "%s\\n" "nameserver 127.0.0.1" > /etc/resolv.conf
    sleep 2

    # Write new iptables rules on file: "/etc/iptables/iptables.rules"
    # reference: https://wiki.archlinux.org/index.php/Tor#Transparent_Torification
    # reference file: "/usr/share/archtorify/data/iptables.rules"
    printf "${blue}%s${endc} ${green}%s${endc}\\n" "::" "Set new iptables rules... "

    if ! cp -vf "$config_dir/iptables.rules" /etc/iptables/iptables.rules; then
        printf "\\n${red}%s${endc}\\n" \
            "[ failed ] can't set '/etc/iptables/iptables.rules'"
        exit 1
    fi
    sleep 4

    # Start tor.service
    printf "${blue}%s${endc} ${green}%s${endc}\\n" "::" "Start Tor service... "
    if ! systemctl start tor.service iptables 2>/dev/null; then
        printf "\\n${red}%s${endc}\\n" "[ failed ] systemd error, exit!"
        exit 1
    fi
    sleep 6

    printf "${cyan}%s${endc} ${green}%s${endc}\\n" "[ ok ]" "Tor service is active"

    printf "${cyan}%s${endc} ${green}%s${endc}\\n" \
        "[ ok ]" "Transparent Proxy activated, your system is under Tor"
    printf "${cyan}%s${endc} ${green}%s${endc}\\n" \
        "[ info]" "Try '$program --status' for check the program status"
}


# Stop transparent proxy
stop() {
    check_root
    printf "${cyan}%s${endc} ${green}%s${endc}\\n" "==>" "Stopping Transparent Proxy"
    sleep 2

    ## Resets default settings
    # Flush current iptables rules
    printf "${blue}%s${endc} ${green}%s${endc}" "::" "Flush iptables rules... "
    iptables -F
    iptables -t nat -F
    printf "${white}%s${endc}\\n" "Done"

    # Restore iptables
    printf "${blue}%s${endc} ${green}%s${endc}\\n" \
        "::" "Restore the default iptables rules... "

    rm -v /etc/iptables/iptables.rules
    iptables-restore < "$backup_dir/iptables.backup"
    sleep 2

    # Stop tor.service
    printf "${blue}%s${endc} ${green}%s${endc}" "::" "Stop Tor service... "
    systemctl stop tor.service
    printf "${white}%s${endc}\\n" "Done"
    sleep 4

    # Restore /etc/resolv.conf --> default nameserver
    printf "${blue}%s${endc} ${green}%s${endc}\\n" \
        "::" "Restore '/etc/resolv.conf' file with default DNS"
    rm -v /etc/resolv.conf
    cp -vf "$backup_dir/resolv.conf.backup" /etc/resolv.conf
    sleep 2

    # Restore default "torrc" file
    printf "${blue}%s${endc} ${green}%s${endc}\\n" \
        "::" "Restore '/etc/tor/torrc' file with default tor settings"
    cp -vf "$backup_dir/torrc.backup" /etc/tor/torrc
    sleep 1

    # Enable firewall ufw
    enable_ufw

    ## End
    printf "${cyan}%s${endc} ${green}%s${endc}\\n" \
        "[-]" "Transparent Proxy stopped"
}


# Function for check public IP
check_ip() {
    printf "${cyan}%s${endc} ${green}%s${endc}\\n" \
        "==>" "Checking your public IP, please wait..."

    # curl request: http://ipinfo.io/geo
    # TODO: add a better error handling
    if ! external_ip="$(curl -s -m 10 ipinfo.io/geo)"; then
        printf "${red}%s${endc}\\n" "[ failed ] curl: HTTP request error!"
        printf "${red}%s${endc}\\n" \
            "Please check your network settings."
        exit 1
    fi

    # Print output
    printf "${blue}%s${endc} ${green}%s${endc}\\n" "::" "IP Address Details:"
    printf "${white}%s${endc}" "$external_ip" | tr -d '"{}' | sed 's/ //g'
}


## Check_status function
# Function for check status of program and services:
# check --> tor.service
# check --> tor settings
# check --> public IP
check_status () {
    check_root

    # Check status of tor.service
    printf "${cyan}%s${endc} ${green}%s${endc}\\n" \
        "==>" "Check current status of Tor service"

    if systemctl is-active tor.service > /dev/null 2>&1; then
        printf "${cyan}%s${endc} ${green}%s${endc}\\n\\n" \
            "[ ok ]" "Tor service is active"
    else
        printf "${red}%s${endc}\\n" "[-] Tor service is not running! exiting..."
        exit 1
    fi

    # Check tor network settings
    # make http request with curl at "https://check.torproject.org/"
    # and grep the necessary strings from the html page to test connection
    # with tor
    printf "${cyan}%s${endc} ${green}%s${endc}\\n" \
        "==>" "Check Tor network settings"

    local host_port="localhost:9050"
    local url="https://check.torproject.org/"

    # curl: '-L' and 'tac' for avoid error: (23) Failed writing body
    # https://github.com/kubernetes/helm/issues/2802
    # https://stackoverflow.com/questions/16703647/why-curl-return-and-error-23-failed-writing-body
    if curl --socks5 "$host_port" --socks5-hostname "$host_port" -sL "$url" \
        | cat | tac | grep -q 'Congratulations'; then
        printf "${cyan}%s${endc} ${green}%s${endc}\\n\\n" \
            "[ ok ]" "Your system is configured to use Tor"
    else
        printf "${red}%s${endc}\\n\\n" "Your system is not using Tor"
        exit 1
    fi

    # Check current public IP
    check_ip
    exit 0
}


# Restart tor.service and change IP
restart() {
    check_root

    printf "${cyan}%s${endc} ${green}%s${endc}\\n" \
        "==>" "Restart Tor service and change IP"
    # systemctl stop/start service
    systemctl stop tor.service iptables
    sleep 3
    systemctl start tor.service iptables
    sleep 2

    printf "${cyan}%s${endc} ${green}%s${endc}\\n\\n" "[ ok ]" "Tor Exit Node changed"

    # Check current public ip
    check_ip
}


# Print "nerd style" help menù
usage() {
    printf "${green}%s${endc}\\n" "$program $version"
    printf "${green}%s${endc}\\n\\n" "Transparent proxy through Tor for Arch Linux"

    printf "${green}%s${endc}\\n\\n" "Usage:"

    printf "${white}%s${endc} ${red}%s${endc} ${white}%s${endc} ${red}%s${endc}\\n" \
        "┌─╼" "$USER" "╺─╸" "$(hostname)"
    printf "${white}%s${endc} ${green}%s${endc}\\n\\n" "└───╼" "./$program [option]"

    printf "${green}%s${endc}\\n\\n" "Options:"

    printf "${white}%-12s${endc} ${green}%s${endc}\\n" \
        "--help"      "show this help message and exit"
    printf "${white}%-12s${endc} ${green}%s${endc}\\n" \
        "--start"     "start transparent proxy through tor"
    printf "${white}%-12s${endc} ${green}%s${endc}\\n" \
        "--stop"      "reset iptables and return to clear navigation"
    printf "${white}%-12s${endc} ${green}%s${endc}\\n" \
        "--status"    "check status of program and services"
    printf "${white}%-12s${endc} ${green}%s${endc}\\n" \
        "--checkip"   "check only public IP"
    printf "${white}%-12s${endc} ${green}%s${endc}\\n" \
        "--restart"   "restart tor service and change IP"
    printf "${white}%-12s${endc} ${green}%s${endc}\\n" \
        "--version"   "display program and tor version then exit"
    exit 0
}


# Cases user input
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
        usage
        exit 0
        ;;
    --)
        printf "${white}%s${endc}\\n" "$program: '$1' it requires an argument!" >&2
        printf "${white}%s${endc}\\n" "Try '$program --help' for more information."
        exit 1
        ;;
    --*)
        printf "${white}%s${endc}\\n" "$program: Invalid option '$1' !" >&2
        printf "${white}%s${endc}\\n" "Try '$program --help' for more information."
        exit 1
        ;;
    *)
        printf "${white}%s${endc}\\n" "$program: Invalid option $1!" >&2
        printf "${white}%s${endc}\\n" "Try '$program --help' for more information."
        exit 1
esac

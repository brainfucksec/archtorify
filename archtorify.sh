#!/usr/bin/env bash

# Program: archtorify.sh
# Version: 1.10.0
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
readonly version="1.10.0"
readonly author="Brainfuck"
readonly git_url="https://github.com/brainfucksec/archtorify"

# Define colors for terminal output
export red=$'\e[0;91m'
export green=$'\e[0;92m'
export blue=$'\e[0;94m'
export white=$'\e[0;97m'
export cyan=$'\e[0;96m'
export endc=$'\e[0m'

## Directories
# Set program's directories and files
# backup files: /opt/archtorify/backups
# configuration files: /opt/archtorify/cfg
readonly backup_dir="/opt/archtorify/backups"
readonly config_dir="/opt/archtorify/cfg"


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


# check if the program run as a root
check_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        printf "\\n${red}%s${endc}\\n" \
            "[ failed ] Please run this program as a root!" 2>&-
        exit 1
    fi
}


# display program and Tor version then exit
print_version() {
    printf "${white}%s${endc}\\n" "$program version $version"
    printf "${white}%s${endc}\\n" "$(tor --version)"
    exit 0
}


## Functions for firewall ufw (launched only if ufw exist)
# check ufw status:
# if installed and/or active disable it, if isn't installed, do nothing,
# don't display nothing to user, simply jump to next function
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


## enable ufw
# often, if ufw isn't installed, do nothing and jump to the next function
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
# check if archtorify is properly configured, begin ...
check_defaults() {
    # check dependencies (tor)
    declare -a dependencies=("tor");
    for package in "${dependencies[@]}"; do
        if ! hash "$package" 2>/dev/null; then
            printf "${red}%s${endc}\\n" \
                "[ FAILED ] '$package' isn't installed, exit";
            exit 1
        fi
    done

    ## Check if program's directories exist
    # backup dir: /opt/archtorify/backups
    # config dir: /opt/archtorify/cfg
    if [ ! -d "$backup_dir" ]; then
        printf "${red}%s${endc}\\n" \
            "[ failed ] '$backup_dir' not exist, run makefile first!";
        exit 1
    fi

    if [ ! -d "$config_dir" ]; then
        printf "${red}%s${endc}\\n" \
            "[ failed ] '$config_dir' not exist, run makefile first!";
        exit 1
    fi

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

    # if this file is not configured, configure it now
    if [[ $VAR1 -ne 0 ]] || [[ $VAR2 -ne 0 ]] || [[ $VAR3 -ne 0 ]] || [[ $VAR4 -ne 0 ]]; then
        printf "\n${blue}%s${endc} ${green}%s${endc}\\n" \
            "::" "Setting file: /usr/lib/systemd/system/tor.service"

        # backup original 'tor.service' file to the backup directory
        if ! cp -vf /usr/lib/systemd/system/tor.service "$backup_dir/tor.service.backup"; then
            printf "${red}%s\\n %s${endc}\\n" \
                "[ failed ] can't copy original 'tor.service' file to the backup directory."
            exit 1
        fi

        # copy new 'tor.service' file with new settings
        if ! cp -vf "$config_dir/tor.service" /usr/lib/systemd/system/tor.service; then
            printf "${red}%s${endc}\\n" \
                "[ failed ] can't set '/usr/lib/systemd/system/tor.service'"
            exit 1
        fi
    fi

    ## Check permissions of directory: "/var/lib/tor"
    # correct: drwx------  tor tor
    if [[ "$(stat -c '%U' /var/lib/tor)" != "tor" ]] &&
        [[ "$(stat -c '%a' /var/lib/tor)" != "755" ]]; then
        printf "${blue}%s${endc} ${green}%s${endc}\\n" \
            "::" "Setting permissions of directory: /var/lib/tor"

        # exec
        chown -R tor:tor /var/lib/tor
        sleep 1
        chmod -R 755 /var/lib/tor
        sleep 1
        systemctl --system daemon-reload

        printf "${white}%s${endc}\\n" "... Done"
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

    # if this file is not configured, configure it now
    if [ $VAR5 -ne 0 ] || [ $VAR6 -ne 0 ] || [ $VAR7 -ne 0 ] || [ $VAR8 -ne 0 ]; then
        printf "\n${blue}%s${endc} ${green}%s${endc}\n" "::" "Setting file: /etc/tor/torrc"

        # backup original tor 'torrc' file to the backup directory
        if ! cp -vf /etc/tor/torrc "$backup_dir/torrc.backup"; then
            printf "${red}%s${endc}\\n" \
                "[ failed ] can't copy original tor 'torrc' file to the backup directory"
            exit 1
        fi

        # copy new 'torrc' filw with settings for archtorify
        if ! cp -vf "$config_dir/torrc" /etc/tor/torrc; then
            printf "${red}%s${endc}\\n" \
                "[ failed ] can't set '/etc/tor/torrc'"
            exit 1
        fi
    fi
}


## Start transparent proxy
main() {
    banner
    check_root
    check_defaults

    # check status of tor.service and stop it if is active (for better security)
    if systemctl is-active tor.service >/dev/null 2>&1; then
        systemctl stop tor.service
    fi

    printf "\\n${cyan}%s${endc} ${green}%s${endc}\\n" "==>" "Starting Transparent Proxy"
    disable_ufw
    sleep 3

    ## Begin iptables settings:
    # save current iptables rules
    printf "${blue}%s${endc} ${green}%s${endc}" "::" "Backup iptables rules... "

    if ! iptables-save > "$backup_dir/iptables.backup"; then
        printf "${red}%s${endc}\\n" \
            "[ failed ] can't copy iptables rules to backup directory"
        exit 1
    fi

    printf "${white}%s${endc}\\n" "Done"
    sleep 2

    # flush current iptables rules
    printf "${blue}%s${endc} ${green}%s${endc}" "::" "Flush iptables rules... "
    iptables -F
    iptables -t nat -F
    printf "${white}%s${endc}\\n" "Done"

    # configure system's DNS resolver to use Tor's DNSPort on the loopback interface
    # i.e. write nameserver 127.0.0.1 to 'etc/resolv.conf' file
    printf "${blue}%s${endc} ${green}%s${endc}\\n" \
        "::" "Configure system's DNS resolver to use Tor's DNSPort"

    if ! cp -vf /etc/resolv.conf "$backup_dir/resolv.conf.backup"; then
        printf "${red}%s${endc}\\n" \
            "[ failed ] can't copy resolv.conf to the backup directory"
        exit 1
    fi

    printf "%s\\n" "nameserver 127.0.0.1" > /etc/resolv.conf
    sleep 2

    # write new iptables rules on file: "/etc/iptables/iptables.rules"
    # NOTE --> added exception rules on iptables for allow traffic on Virtualbox NAT Network
    # '--ipv4 -A OUTPUT -d 10.0.0.0/8 -j ACCEPT'
    printf "${blue}%s${endc} ${green}%s${endc}\\n" "::" "Set new iptables rules... "

    if ! cp -vf "$config_dir/iptables.rules" /etc/iptables/iptables.rules; then
        printf "${red}%s${endc}\\n" \
            "[ failed ] can't set '/etc/iptables/iptables.rules'"
        exit 1
    fi
    sleep 4

    # start tor.service
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
        "[ info]" "use '--status' argument for check the program status"
}


## Stop transparent proxy
stop() {
    check_root
    printf "${cyan}%s${endc} ${green}%s${endc}\\n" "==>" "Stopping Transparent Proxy"
    sleep 2

    ## Resets default settings
    # flush current iptables rules
    printf "${blue}%s${endc} ${green}%s${endc}" "::" "Flush iptables rules... "
    iptables -F
    iptables -t nat -F
    printf "${white}%s${endc}\\n" "Done"

    # restore iptables
    printf "${blue}%s${endc} ${green}%s${endc}\\n" \
        "::" "Restore the default iptables rules... "

    rm -v /etc/iptables/iptables.rules
    iptables-restore < "$backup_dir/iptables.backup"
    sleep 2

    # stop tor.service
    printf "${blue}%s${endc} ${green}%s${endc}" "::" "Stop Tor service... "
    systemctl stop tor.service
    printf "${white}%s${endc}\\n" "Done"
    sleep 4

    # restore /etc/resolv.conf --> default nameserver
    printf "${blue}%s${endc} ${green}%s${endc}\\n" \
        "::" "Restore '/etc/resolv.conf' file with default DNS"
    rm -v /etc/resolv.conf
    cp -vf "$backup_dir/resolv.conf.backup" /etc/resolv.conf
    sleep 2

    # restore default 'torrc' file
    printf "${blue}%s${endc} ${green}%s${endc}\\n" \
        "::" "Restore '/etc/tor/torrc' file with default tor settings"
    cp -vf "$config_dir/torrc.default" /etc/tor/torrc
    sleep 1

    # enable firewall ufw
    enable_ufw

    ## End
    printf "${cyan}%s${endc} ${green}%s${endc}\\n" \
        "[-]" "Transparent Proxy stopped"
}


## Function for check public IP
check_ip() {
    printf "${cyan}%s${endc} ${green}%s${endc}\\n" \
        "==>" "Checking your public IP, please wait..."

    # curl request: http://ipinfo.io/geo
    if ! external_ip="$(curl -s -m 10 ipinfo.io/geo)"; then
        printf "${red}%s${endc}\n" "[ failed ] curl: HTTP request error!"
        exit 1
    fi

    # print output
    printf "${blue}%s${endc} ${green}%s${endc}\\n" "::" "IP Address Details:"
    printf "${white}%s${endc}" "$external_ip" | tr -d '"{}' | sed 's/ //g'
}


## Check_status function
# function for check status of program and services:
# check --> tor.service
# check --> tor settings
# check --> public IP
check_status () {
    check_root

    # check status of tor.service
    printf "${cyan}%s${endc} ${green}%s${endc}\\n" \
        "==>" "Check current status of Tor service"

    if systemctl is-active tor.service > /dev/null 2>&1; then
        printf "${cyan}%s${endc} ${green}%s${endc}\\n\\n" \
            "[ ok ]" "Tor service is active"
    else
        printf "${red}%s${endc}\\n" "[-] Tor service is not running! exiting..."
        exit 1
    fi

    # check tor network settings
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

    # check current public IP
    check_ip
    exit 0
}


## Restart tor.service and change IP
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

    # check current public ip
    check_ip
}


# print nice "nerd style" help menù
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


## Cases user input
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
        printf "${red}%s${endc}\\n" "[ failed ] '$1' it requires an argument!" >&2
        printf "${white}%s${endc}\\n" "use $program --help for more informations"
        exit 1
        ;;
    --*)
        printf "${red}%s${endc}\\n" "[ failed ] Invalid option '$1' !" >&2
        printf "${white}%s${endc}\\n" "use $program --help for more informations"
        exit 1
        ;;
    *)
        printf "${red}%s${endc}\\n" "[ failed ] Invalid option '$1' !" >&2
        printf "${white}%s${endc}\\n" "use $program --help for more informations"
        exit 1
esac

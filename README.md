## Archtorify v1.7.0

#### Transparent proxy through Tor for Arch Linux

#### Archtorify is a program for simplify the configuration of transparent proxy trough Tor Network




### Configuration

#### Update system and install dependencies (tor and curl)
```bash
pacman -Syu
pacman -S tor wget
```

Note: The program check is firewall ufw is installed, but isn't a dependency


#### Modify the systemd's tor service file '/usr/lib/systemd/system/tor.service' as follows (check file 'tor.service-example' if you need help):
```bash
[Service]
User=root
Group=root
Type=simple
```


#### The process of tor will be run as tor user. For this purpose change user and group ID to tor and also make it writeable: 
```bash
chown -R tor:tor /var/lib/tor
chmod -R 755 /var/lib/tor
```


#### Modify '/etc/tor/torrc' file,  add the follows:
```bash
User tor
SocksPort 9050
DNSPort 5353
TransPort 9040
```


#### Now save changes and run the daemon:
```bash
systemctl --system daemon-reload
```




### Start Program

#### Use help argument or run the program without arguments for help menu':
```bash
./archtorify.sh --help
...

└───╼ ./archtorify --argument

Arguments available:

--help      show this help message and exit
--start     start transparent proxy for tor
--stop      reset iptables and return to clear navigation
--status    check status of program and services
--checkip   check only public IP
--restart   restart tor service and change IP
--version   display program and tor version then exit

```


#### Start Transparent Proxy with --start argument
```bash
./archtorify.sh --start
...

:: Starting Transparent Proxy

```




#### [ NOTES ]:

The steps 2 and 5 will be repeated after every update of tor, anyway the program check these files for you.


Configuration of transparent proxy on Arch Linux depends on your network configuration, please read these Arch Wiki pages: 

Tor: https://wiki.archlinux.org/index.php/Tor

Network Configuration: https://wiki.archlinux.org/index.php/Network_configuration


Tor project page about transparent proxy and DNS proxy: https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy


New Tor Entry Guards: this is usually something to avoid unless you know what you are doing, for more information please read here: 

https://www.whonix.org/wiki/Tor#Non-Persistent_Entry_Guards 

https://forums.whonix.org/t/persistent-tor-entry-guard-relays-can-make-you-trackable-across-different-physical-locations/2090

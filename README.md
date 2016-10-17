## Archtorify v1.6.2

### Transparent proxy through Tor for Arch Linux


### Instructions

#### 1 - Install dependencies (tor and wget)
```bash
pacman -S tor 

pacman -S wget
```

#### 2 - Modify the systemd's tor service file /usr/lib/systemd/system/tor.service as follows:
```
[Service]
User=root
Group=root
Type=simple
```

#### If you have a problem when edit this file, you can read an example file 'tor.service-example'


#### 3 - The process of tor will be run as tor user. For this purpose change user and group ID to tor and also make it writeable: 
```bash
chown -R tor:tor /var/lib/tor
chmod -R 755 /var/lib/tor
```

#### 4 - Modify /etc/tor/torrc file, add the follows:
```
User tor
SocksPort 9050
DNSPort 53
TransPort 9040
````

#### 5 - Now save changes and run the daemon:
```bash
systemctl --system daemon-reload
```

#### 6 - Chmod and run program as a root 
```bash
chmod +x archtorify.sh

./archtorify --start
```

#### 7 Use help argument or run the program without arguments for help menu'
```bash
./archtorify.sh --help
```



#### Note:

The steps 2 and 5 will be repeated after every update of tor, anyway the program check these files for you.

Configuration of transparent proxy in Arch Linux is little hard, if you have a problem please read the Arch Wiki: https://wiki.archlinux.org/index.php/Tor

Arch Linux Network Configuration: https://wiki.archlinux.org/index.php/Network_configuration

Tor project page about transparent proxy and DNS proxy: https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy

New Tor Entry Guards: this is usually something to avoid unless you know what you are doing, for more information please read here: 

https://www.whonix.org/wiki/Tor#Non-Persistent_Entry_Guards 

https://forums.whonix.org/t/persistent-tor-entry-guard-relays-can-make-you-trackable-across-different-physical-locations/2090








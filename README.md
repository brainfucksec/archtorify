## Archtorify v1.4

### Bash script for transparent proxy through Tor
### Operative System: Arch Linux

### Instructions

#### 1 - Modify the systemd's tor service file /usr/lib/systemd/system/tor.service as follows:
```
[Service]
User=root
Group=root
Type=simple
```

#### If you have a problem when edit this file you can read an example file 'tor.service-example'


#### 2 - The process of tor will be run as tor user. For this purpose change user and group ID to tor and also make it writeable: 
```bash
chown -R tor:tor /var/lib/tor
chmod -R 755 /var/lib/tor
```

#### 3 - Now save changes and run the daemon:
```bash
systemctl --system daemon-reload
```


#### 3 - Modify /etc/tor/torrc file, add the follows:
```
User tor
SocksPort 9050
DNSPort 53
TransPort 9040
````

#### 4 - Start program, chmod and run as a root 
```bash
chmod +x archtorify.sh

./archtorify start
```

#### 5 Use help argument or run the program without arguments for help menu'
```bash
./archtorify.sh help
```



#### Note:

The steps 1 and 2 will be repeated after every update of tor, anyway the program check these files for you.

Configuration of transparent proxy in Arch Linux is little hard, if you have a problem please read the Arch Wiki: https://wiki.archlinux.org/index.php/Tor

Arch Linux Network Configuration: https://wiki.archlinux.org/index.php/Network_configuration

Tor project page about transparent proxy and DNS proxy: https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy







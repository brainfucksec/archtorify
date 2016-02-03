### Archtorify v1.2

#### Torify entire Arch Linux systems 




#### CONFIGS INSTRUCTIONS 


##### 1 - Modify the systemd's tor service file /usr/lib/systemd/system/tor.service as follows:
```bash
[Service]
User=root
Group=root
Type=simple
```

##### 2 - The process will be run as tor user. For this purpose change user and group ID to tor and also make it writeable: 
```bash
chown -R tor:tor /var/lib/tor
chmod -R 755 /var/lib/tor
```

##### Now save changes and run the daemon: systemctl --system daemon-reload


##### 3 - Add the follows at the end of /etc/tor/torrc file:
```bash
User tor
SocksPort 9050
DNSPort 5353
TransPort 9040
````



##### NOTE FOR THE USER

###### Reference: https://wiki.archlinux.org/index.php/Tor 

###### The steps 1 and 2 will be repeated after every update of tor service.

###### Please Note this script don't work if you have netctl because use openresolv.
###### The steps 1 and 2 be repeated after update of tor.

  









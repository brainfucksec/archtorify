### Archtorify v1.3

#### Bash script for transparent proxy trought Tor 




#### Instructions 


##### 1 - Modify the systemd's tor service file /usr/lib/systemd/system/tor.service as follows:
```
[Service]
User=root
Group=root
Type=simple
```


##### 2 - The process will be run as tor user. For this purpose change user and group ID to tor and also make it writeable: 
```
chown -R tor:tor /var/lib/tor
chmod -R 755 /var/lib/tor
```

##### Now save changes and run the daemon: 
```
systemctl --system daemon-reload
```


##### 3 - Add the follows at the end of /etc/tor/torrc file:
```
User tor
SocksPort 9050
DNSPort 53
TransPort 9040
````

##### Note for the users:

###### The steps 1 and 2 will be repeated after every update of tor service.

###### Please Note this script don't work if you have netctl because use openresolv.


##### Reference: https://wiki.archlinux.org/index.php/Tor


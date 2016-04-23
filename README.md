<<<<<<< HEAD
### Archtorify v1.3
=======
### Archtorify v1.2
>>>>>>> 3a61f438139397ca6f6a5d9abd7fb4483372f6b8

#### Bash script for transparent proxy trought Tor 




#### Instructions 


##### 1 - Modify the systemd's tor service file /usr/lib/systemd/system/tor.service as follows:
<<<<<<< HEAD
```
=======
```bash
>>>>>>> 3a61f438139397ca6f6a5d9abd7fb4483372f6b8
[Service]
User=root
Group=root
Type=simple
```

##### 2 - The process will be run as tor user. For this purpose change user and group ID to tor and also make it writeable: 
<<<<<<< HEAD
```
=======
```bash
>>>>>>> 3a61f438139397ca6f6a5d9abd7fb4483372f6b8
chown -R tor:tor /var/lib/tor
chmod -R 755 /var/lib/tor
```

<<<<<<< HEAD
##### Now save changes and run the daemon: 
```
systemctl --system daemon-reload
```


##### 3 - Add the follows at the end of /etc/tor/torrc file:
```
=======
##### Now save changes and run the daemon: systemctl --system daemon-reload


##### 3 - Add the follows at the end of /etc/tor/torrc file:
```bash
>>>>>>> 3a61f438139397ca6f6a5d9abd7fb4483372f6b8
User tor
SocksPort 9050
DNSPort 5353
TransPort 9040
````


<<<<<<< HEAD
##### Note for the users:

###### Reference: https://wiki.archlinux.org/index.php/Tor 

###### The steps 1 and 2 will be repeated after every update of tor service.

###### Please Note this script don't work if you have netctl because use openresolv.
=======
#### Note for the users:

##### [!] The steps 1 and 2 will be repeated after every update of tor service.

##### Reference: https://wiki.archlinux.org/index.php/Tor
>>>>>>> 3a61f438139397ca6f6a5d9abd7fb4483372f6b8

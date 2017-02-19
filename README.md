## Archtorify v1.8.0

#### Archtorify is a program for simplify the configuration of transparent proxy trough Tor Network




#### Configuration

##### Update system and run install.sh:
```bash
pacman -Syyu
cd archtorify/
chmod +x install.sh
./install.sh
```




#### Start Program

##### Use help argument or run the program without arguments for help menu':
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


##### Start Transparent Proxy with --start argument
```bash
./archtorify.sh --start
...

:: Starting Transparent Proxy

```




#### [ NOTES ]:

##### Please note that this program isn't a final solution for a setup of 100% anonimity, for more information about Tor configurations please read these docs:

**Tor Project wiki about Transparent Proxy:** 

https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy


**Whonix Do Not recommendations:** 

https://www.whonix.org/wiki/DoNot


**Whonix wiki about Tor Entry Guards:**

https://www.whonix.org/wiki/<Tor id="Non-Persistent_Entry_Guards"></Tor>

https://forums.whonix.org/t/persistent-tor-entry-guard-relays-can-make-you-trackable-across-different-physical-locations/2090




##### Configuration of transparent proxy on Arch Linux depends on your network configuration, please read these docs from Arch Linux wiki: 

**Tor:** 

https://wiki.archlinux.org/index.php/Tor

**Network Configuration:** 

https://wiki.archlinux.org/index.php/Network_configuration


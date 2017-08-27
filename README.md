## Archtorify v1.9.0

### Program for simplify the configuration of transparent proxy through Tor Network




### Installation

#### Install dependencies:
```bash
sudo pacman -Syu

sudo pacman -S tor
```

#### Package:

AUR: [`archtorify-git`](https://aur.archlinux.org/packages/archtorify-git)


#### Manual installation:
```bash
git clone https://github.com/brainfucksec/archtorify

cd archtorify/

sudo make install
```




### Start Program

#### Use --help argument for help menu':
```bash
sudo archtorify --help
...

└───╼ ./archtorify --argument

Arguments available:
--------------------
--help       show this help message and exit
--start      start transparent proxy through tor
--stop       reset iptables and return to clear navigation
--status     check status of program and services
--checkip    check only public IP
--restart    restart tor service and change IP
--version    display program and tor version then exit
```


#### Start Transparent Proxy with --start argument:
```bash
sudo archtorify --start
```




#### [ NOTES ]

##### Please note that this program is not a final solution for a setup of anonimity at 100%, for more information about Tor configurations please read these docs:

**Tor Project wiki about Transparent Proxy:**

https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy


**Tor General FAQ**

https://www.torproject.org/docs/faq.html.en


**Whonix Do Not recommendations:**

https://www.whonix.org/wiki/DoNot




##### Configuration of transparent proxy on Arch Linux depends on your network configuration, this program not work if you have installed 'openresolv' or 'netctl' (because this programs overwrite the resolv.conf file), please read these docs from Arch Linux wiki:

**Tor:**

https://wiki.archlinux.org/index.php/Tor

**Network Configuration:**

https://wiki.archlinux.org/index.php/Network_configuration

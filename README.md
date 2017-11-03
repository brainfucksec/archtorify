# Archtorify v1.10.0

## Transparent proxy through Tor for Arch Linux


## Installation

#### Install dependencies:
```bash
sudo pacman -Syu

sudo pacman -S tor
```

### Package:

AUR: [`archtorify-git`](https://aur.archlinux.org/packages/archtorify-git)


### Manual installation:
```bash
git clone https://github.com/brainfucksec/archtorify

cd archtorify/

sudo make install
```


## Run program

#### Simply start Transparent Proxy with --start option:

```bash
sudo archtorify --start
```


### [ NOTES ]

#### Please note that this program is not a final solution for a setup of anonimity at 100%, for more information about Tor configurations please read these docs:

#### Tor Project wiki about Transparent Proxy:

https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy

#### Tor General FAQ

https://www.torproject.org/docs/faq.html.en


#### Whonix Do Not recommendations:

https://www.whonix.org/wiki/DoNot


#### Configuration of transparent proxy on Arch Linux depends on your network configuration, this program not work if you have installed 'openresolv' or 'netctl' installed (because this programs overwrite the resolv.conf file), please read these docs from Arch Linux wiki:

#### Tor:

https://wiki.archlinux.org/index.php/Tor

#### Network Configuration:

https://wiki.archlinux.org/index.php/Network_configuration

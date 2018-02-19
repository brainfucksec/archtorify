# archtorify

# About archtorify

archtorify is a shell script for [Arch Linux](https://www.archlinux.org/) which use [iptables](https://www.netfilter.org/projects/iptables/index.html) settings for transparent proxy through Tor, the program also allows you to perform various checks like checking the external ip, or if Tor has been configured correctly.

## What is Transparent Proxy?

Also known as an intercepting proxy, inline proxy, or forced proxy, a transparent proxy intercepts normal communication at the network layer without requiring any special client configuration. Clients need not be aware of the existence of the proxy. A transparent proxy is normally located between the client and the Internet, with the proxy performing some of the functions of a gateway or router.

In the [Tor project wiki](https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy) you find an explanation of what is the "transparent proxy through tor" and related settings.

## Recommendations

archtorify is produced independently from the Tor anonimity software and carries no guarantee from the Tor Project about quality, suitability or anithing else, if you need more information about tor security plese read these docs:

[Tor General FAQ](https://www.torproject.org/docs/faq.html.en)

[Whonix Do Not recommendations](https://www.whonix.org/wiki/DoNot)

Arch Linux is a user-centric distribution, for this, configuration of transparent proxy strongly depends on your network settings, before starting the program make sure you have read the Arch Linux wiki pages [about Tor](https://wiki.archlinux.org/index.php/Tor) and [network configuration](https://wiki.archlinux.org/index.php/Network_configuration)

## Install

#### Note: From version '1.10.1' the program directories are changed, if previous version is installed, remove this first:
```bash
sudo pacman -R archtorify-git
```

#### Install dependencies:
```bash
sudo pacman -Syu

sudo pacman -S tor
```

#### Install Package from AUR:

AUR: [`archtorify-git`](https://aur.archlinux.org/packages/archtorify-git)

#### Manual installation:
```bash
git clone https://github.com/brainfucksec/archtorify

cd archtorify/

sudo make install
```

## Usage

#### Simply start Transparent Proxy with '--start' option:
```bash
sudo archtorify --start
```

#### Like any other unix like program use '--help' option for help menù:
```bash
sudo archtorify --help
```

## Thanks

* This program would not exist without the users of [Arch Linux Community](https://bbs.archlinux.org/) that helped me in the building of the AUR package.

* A special thanks goes also to the [Whonix](https://www.whonix.org/) Team and their [documentation](https://www.whonix.org/wiki/Documentation)

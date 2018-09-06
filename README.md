# archtorify

# About archtorify

archtorify is a shell script for [Arch Linux](https://www.archlinux.org/) which use [iptables](https://www.netfilter.org/projects/iptables/index.html) settings for transparent proxy through Tor, the program also allows you to perform various checks like checking the external ip, or if Tor has been configured correctly.

## What is Transparent Proxy?

Also known as an intercepting proxy, inline proxy, or forced proxy, a transparent proxy intercepts normal communication at the network layer without requiring any special client configuration. Clients need not be aware of the existence of the proxy. A transparent proxy is normally located between the client and the Internet, with the proxy performing some of the functions of a gateway or router.

In the [Tor project wiki](https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy) you find an explanation of what is the "Transparent Proxy through Tor" and related settings.

## Recommendations

archtorify is produced independently from the Tor anonimity software and carries no guarantee from the Tor Project about quality, suitability or anything else, **please read these documents to know how to use the Tor network safely:**

[Tor General FAQ](https://www.torproject.org/docs/faq.html.en)

[Whonix Do Not recommendations](https://www.whonix.org/wiki/DoNot)

Arch Linux is a user-centric distribution, for this, configuration of transparent proxy strongly depends on your network settings, before starting the program make sure you have read the Arch Linux wiki pages [about Tor](https://wiki.archlinux.org/index.php/Tor) and [network configuration](https://wiki.archlinux.org/index.php/Network_configuration)

## Install

### Install dependencies:
```bash
sudo pacman -Syu

sudo pacman -S tor
```

### Install Package from AUR:

AUR: [`archtorify-git`](https://aur.archlinux.org/packages/archtorify-git)

### Manual installation:
```bash
git clone https://github.com/brainfucksec/archtorify

cd archtorify/

sudo make install

sudo reboot
```

## Usage

**archtorify [option****]**

### Options:

**-t, --tor**

    start transparent proxy through tor

**-c, --clearnet**

    reset iptables and return to clearnet navigation

**-s, --status**

    check status of program and services

**-i, --ipinfo**

    show public IP

**-r, --restart**

    restart tor service and change IP

## Thanks

* This program would not exist without the users of [Arch Linux Community](https://bbs.archlinux.org/) that helped me in the building of the AUR package.

* This program could not exist without the guides of the [Tor Project official website](https://www.torproject.org/)

* A special thanks goes also to the [Whonix](https://www.whonix.org/) Team and their [documentation](https://www.whonix.org/wiki/Documentation)

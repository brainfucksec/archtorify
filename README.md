# archtorify

# About archtorify

archtorify is a shell script for [Arch Linux](https://www.archlinux.org/) which use [iptables](https://www.netfilter.org/projects/iptables/index.html) settings for create a transparent proxy through TorNetwork, the program also allows you to perform various checks like checking the Tor Exit Node (i.e. your public IP when you are under Tor proxy) or if Tor has been configured correctly.

## What is Transparent Proxy through Tor?

Transparent proxy is an intermediary system that sit between a user and a content provider. When a user makes a request to a web server, the transparent proxy intercepts the request to perform various actions including caching, redirection and authentication.

![alt text](https://imgur.com/c9canu4.png)

Transparent proxy via Tor means that every network application will make its TCP connections through Tor; no application will be able to reveal your IP address by connecting directly.
In simple terms, with archtorify you can redirect all traffic of your Arch Linux operating system through the Tor Network.

In the [Tor project wiki](https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy) you find an explanation of what is the **"Transparent Proxy through Tor"** and related settings.
you should read it.

## Recommendations and security considerations

**archtorify is produced independently from the Tor anonimity software and carries no guarantee from the Tor Project about quality, suitability or anything else**, please read these documents to know how to use the Tor network safely:

[Tor General FAQ](https://www.torproject.org/docs/faq.html.en)

[Whonix Do Not recommendations](https://www.whonix.org/wiki/DoNot)

**archtorify provides transparent proxy management on Tor but does not provide 100% anonimity**.

From [Arch Linux Wiki](https://wiki.archlinux.org/index.php/Tor) about Transparent Torification: Using iptables to transparently torify a system affords comparatively strong leak protection, but it is not a substitute for virtualized torification applications such as Whonix, or TorVM.
Applications can still learn your computer's hostname, MAC address, serial number, timezone, etc. and those with root privileges can disable the firewall entirely. In other words, transparent torification with iptables protects against accidental connections and DNS leaks by misconfigured software, it is not sufficient to protect against malware or software with serious security vulnerabilities.

For this, you should change at least the hostname and the MAC address:

[Setting the Hostname on Arch Linux](https://wiki.archlinux.org/index.php/Network_configuration#Set_the_hostname)

[Changing MAC Address on Linux](https://wiki.archlinux.org/index.php/MAC_address_spoofing)

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

**archtorify [option]**

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

* This program would not exist without the users of [Arch Linux Community](https://bbs.archlinux.org/) that helped me in the building of the AUR package and the guides of the [Tor Project official website](https://www.torproject.org/)

* A special thanks goes also to the [Whonix](https://www.whonix.org/) Team and their [documentation](https://www.whonix.org/wiki/Documentation)

## Donations

This is a project made with a lot of motivation to collaborate in the computer security community, if you liked the features. I invite you to make a donation.

**BITCOIN:** 1B39SnAXcR2bkxNpNy3AuckgaTshqNc2ce

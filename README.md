<!--<img src="https://a.pomf.cat/fuqxrf.png"></img>-->

## CDNRECON - A Content Delivery Network recon tool

<b>CDNRECON is a reconnaissance tool that tries to find the origin or backend IP address of a website protected by a CDNs reverse proxy. You can use it to get a head start when penetration testing a client protected by one aswell as to find possible misconfigurations on your own server. What ever your use case may be, CDNRECON can also be used as a general recon / scanning tool since it automates some common recon tasks in the process. These include: finding common subdomains, checking for open ports, searching and returning data from Shodan and Censys, testing the IDS / WAF of the target server and more.

Shodan and Censys API keys are NOT required. Altough it's recommended to supply them for maximum output, CDNRECON tries other things before using them.

<b>The CDNs CDNRECON detects automatically (or atleast tries to):
- Cloudflare
- Akamai
- Blazingfast

<b>Heres some sample output from CDNRECON:



## Installation and usage

<b>Requires atleast python version 3.6 since it uses f-strings.
>It should work on any Linux distro. Tested on Arch Linux.

<b>Clone the repository
```
$ sudo git clone https://github.com/Juuso1337/CDNRECON
```
<b>Install the required depencies
```
$ cd CDNRECON
$ pip3 install -r requirements.txt
```
<b>Sample usage guide

```
$ python3 main.py example.com shodan-key
```
<b> For more in-depth usage info, supply the -h flag (python3 main.py -h).

## Censys and Shodan guide
<b>Register an account on https://search.censys.io/register and https://account.shodan.io/ (it's totally free).


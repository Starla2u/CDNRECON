<img src="https://a.pomf.cat/fuqxrf.png"></img>

## Tries to find non-proxied IP addresses from a website that uses Cloudflares WAF.

<b>EnumFlare is a simple script that scans the target domain for valid subdomains, checks their IP addresses, verifies that they belong to Cloudflare, gets <b>their Ray-IDs, countries and optionally returns data from Shodan for leaked addresses. <i>(if any get found)</i>

<b>Results get saved in to "domain.com-results.txt" in the same directory that EnumFlare is in.

## Checking if the nameservers point to cloudflare (not required)
<img src="https://a.pomf.cat/cxgydc.png"></img>

## Checking for common subdomains and their IP addresses
<img src="https://a.pomf.cat/gcfsdx.png"></img>

## Checks wether the IP addresses belong to Cloudflare or not
<img src="https://a.pomf.cat/pakcyt.png"></img>

## If leaked addresses are found, it searches them on Shodan
<img src="https://a.pomf.cat/ihxnkr.png"></img>

<b>To get an API key for shodan, simply sign up on their website at https://shodan.io and head over to the account page.

<img src="https://a.pomf.cat/nadhtv.png"></img>



## Installation and usage guide
>Requires atleast Python 3.6 since it uses f-strings. Tested on Arch Linux. No guarantees that this will work on Windows.

```
git clone https://github.com/Juuso1337/enumflare
```
```
pip3 install -r requirements.txt
```
```
python3 main.py <DOMAIN.com> <SHODAN_API_KEY>
```
>Strictly for educational purposes. EnumFlare uses publically available data efficiently.

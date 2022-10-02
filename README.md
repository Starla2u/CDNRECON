<img src="https://a.pomf.cat/qbbayz.png"></img>

## Find the real IP address of a Cloudflare WAF protected website.

<b>EnumFlare tries common subdomains and if it finds them, gets their IP addresses and checks if they're from Cloudflare. If they're not, you can supply a Shodan API key to get detailed information from a leaked IP address.
```
git clone https://github.com/Juuso1337/enumflare
```
```
pip3 install -r requirements.txt
```
```
python3 main.py <DOMAIN> <SHODAN_API_KEY> (shodan is optional=
```

# recon
This is a script to chain together various bug bounty tools to check for simple issue and build a set of resources to base manual testing on. This is a continual work in progress, as I learn more.

The tools used are:

Subdomain enumeration:
* [Amass](https://github.com/OWASP/Amass)
* [Assetfinder](https://github.com/tomnomnom/assetfinder)
* [Subfinder](https://github.com/projectdiscovery/subfinder)
* [DNSBuffer](https://tls.bufferover.run/dns?q=)
* [dnsgen](https://github.com/ProjectAnte/dnsgen)

Subdomain verification:
* [massdns](https://github.com/blechschmidt/massdns)
* [wildcheck](https://github.com/theblackturtle/wildcheck)
* [httprobe](https://github.com/tomnomnom/httprobe)

Finding URLs:
* [Hakrawler](https://github.com/hakluke/hakrawler)

Checking for XSS
* [Dalfox](https://github.com/hahwul/dalfox)

Configuration settings can be put in `config.py`. The links above all have installation instructions, or you can take a look at my script [update-kali](https://github.com/rafaelh/update-kali) for a more automated approach.

# recon
This is a script to chain together various bug bounty tools to check for simple issue and build a set of resources to base manual testing on. This is a continual work in progress, as I learn more.

The tools used are:

Subdomain enumeration:
* [Amass](https://github.com/OWASP/Amass)
* [assetfinder](https://github.com/tomnomnom/assetfinder)
* [subfinder](https://github.com/projectdiscovery/subfinder)
* [DNSBuffer](https://tls.bufferover.run/dns?q=)
* [dnsgen](https://github.com/ProjectAnte/dnsgen)

Subdomain verification:
* [massdns](https://github.com/blechschmidt/massdns) - confirm the subdomains resolve
* [wildcheck](https://github.com/theblackturtle/wildcheck) - remove wildcard domains (eg *.example.com)
* [httprobe](https://github.com/tomnomnom/httprobe) - see which domains have responding web servers

Finding URLs:
* [hakrawler](https://github.com/hakluke/hakrawler) - crawl the subdomains for links
* [getallurls](https://github.com/lc/gau) - get all known links from alienvault, wayback & common crawl

Checking for XSS
* [dalfox](https://github.com/hahwul/dalfox)

Configuration settings can be put in `config.py`. The links above all have installation instructions, or you can take a look at my script [update-kali](https://github.com/rafaelh/update-kali) for a more automated approach.

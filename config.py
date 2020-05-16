# Location of Amass config.ini
# An example is available at https://github.com/OWASP/Amass/blob/master/examples/config.ini

amass_config = '/home/rafael/x/notes/automation/amass_config.ini'

# Assetfinder variables (these will be exported if set)
FB_APP_ID = '' # Facebook (https://developers.facebook.com)
FB_APP_SECRET = ''
VT_API_KEY = '' # VirusTotal (https://developers.virustotal.com/reference)
SPYSE_API_TOKEN = '' # Spyse (https://spyse.com/apidocs)

# Massdns resolver file, depending on where you've installed it
massdns_resolvers = "/opt/massdns/lists/resolvers.txt"

# Domain for blind XSS checking with dalfox
# Get your own at https://xsshunter.com
xsshunter_domain = "https://rafaelh.xss.ht"
custom_xss_payloads = "/home/rafael/x/notes/automation/xss_alert.txt"
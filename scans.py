import apt
import os
import sys

def print_bold_green(message):
    """ Prints a message to the console prefixed with a green '>>>' """
    print("\n\033[1;32;40m>>> \033[1;37;40m" + message + "\033[0;37;0m")

def print_green(message):
    """ Prints a message to the console prefixed with a green '[*]' """
    print("[\033[0;32;40m*\033[0;37;40m] " + message + "\033[0;37;0m")

def print_yellow(message):
    """ Prints a message to the console prefixed with a yellow '[*]' """
    print("[\033[1;33;40m*\033[0;37;40m] " + message + "\033[0;37;0m")

def print_grey(message):
    """ Prints a message to the console prefixed with a grey '[*]' """
    print("[\033[0;37;40m*\033[0;37;40m] " + message + "\033[0;37;0m")

def print_red(message):
    """ Prints a message to the console prefixed with a red '[*]' """
    print("[\033[0;31;40m*\033[0;37;40m] " + message + "\033[0;37;0m")

def create_directory(directory):
    ''' Checks if the specified directory exists, and creates it if not '''
    if os.path.exists(directory):
        print_grey("Directory exists: " + directory)
    else:
        print_green("Creating directory: " + directory)
        cmdstring = "mkdir " + directory
        os.system(cmdstring)

def run_checks(amass_config):
    ''' Confirm that all needed tools and config is available *before* wasting any time '''
    if not os.path.exists(amass_config):
        print_yellow("Amass config not found. Results may not be as complete.")

    packages_to_check = ['amass', 'gobuster', 'golang', 'jq']
    apt_cache = apt.Cache()
    for package in packages_to_check:
        if not apt_cache[package].is_installed:
            print_red(package + "is required for this script. Exiting.")
            sys.exit(1)

def count_results(tool, output_file):
    count = 0
    with open(output_file, 'r') as f:
        for line in f:
            count += 1
    print_green(tool + " total number of results: " + str(count))

def run_amass(target, amass_config):
    ''' Runs amass with the specified config file '''
    print_bold_green("Running Amass to find sub-domains")

    output_file = target + "/" + target + ".amass.txt"
    if not os.path.exists(output_file):
        if os.path.exists(amass_config):
            print_green("Using Amass config " + amass_config)
            cmdstring = "amass enum -config " + amass_config + " -brute -d " + target + " -o " + \
                        target + "/" + target + ".amass.txt"
        else:
            print_grey("Not using config.ini")
            cmdstring = "amass enum -brute -d " + target + " -o " + output_file
        os.system(cmdstring)
    else:
        print_yellow("Previous amass results exist. Skipping.")
    count_results('Amass', output_file)
    # need to define and add -min-for-recursive 3

def run_assetfinder(target, FB_APP_ID, FB_APP_SECRET, VT_API_KEY, SPYSE_API_TOKEN):
    ''' Runs Assetfinder after exporting environment variables '''
    print_bold_green("Running Assetfinder to find sub-domains")
    output_file = target + "/" + target + ".assetfinder.txt"

    if not os.path.exists(output_file):
        if FB_APP_ID: os.environ["FB_APP_ID"] = FB_APP_ID
        if FB_APP_SECRET: os.environ["FB_APP_SECRET"] = FB_APP_SECRET
        if VT_API_KEY: os.environ["VT_API_KEY"] = VT_API_KEY
        if SPYSE_API_TOKEN: os.environ["SPYSE_API_TOKEN"] = SPYSE_API_TOKEN

        cmdstring = "assetfinder -subs-only " + target + " > " + output_file
        os.system(cmdstring)
    else:
        print_yellow("Previous Assetfinder results exist. Skipping.")
    count_results('Assetfinder', output_file)

def run_subfinder(target):
    ''' Runs Subfinder to find subdomains '''
    print_bold_green("Running Subfinder to find sub-domains")
    output_file = target + "/" + target + ".subfinder.txt"

    if not os.path.exists(output_file):
        cmdstring = "subfinder -d " + target + " -o " + output_file
        os.system(cmdstring)
    else:
        print_yellow("Previous Subfinder results exist. Skipping.")
    count_results('Subfinder', output_file)

def run_dnsbuffer(target):
    ''' Gets subdomains from Rapid7 '''
    print_bold_green("Running DNS Buffer to find sub-domains")
    output_file = target + "/" + target + ".bufferover.txt"

    if not os.path.exists(output_file):
        cmdstring = "curl -s https://dns.bufferover.run/dns?q=." + target + " | jq -r .FDNS_A[] | " \
                    "cut -d',' -f2 > " + output_file
        os.system(cmdstring)
    else:
        print_yellow("Previous dnsbuffer results exist. Skipping.")
    count_results('DNSBuffer', output_file)

def combine_subdomain_results(target):
    ''' Combine all subdomain tool results and remove duplicates '''
    print_bold_green("Combining subdomain results")

    output_file = target + "/" + target + ".combined.txt"
    cmdstring = "sort " + target + "/*.txt | uniq > " + output_file
    os.system(cmdstring)
    count_results('Combined', output_file)
    # Need to add the target itself to the domain lists, before uniq is run
    # Need to name the files to combine - *.txt will mess up on subsequent runs

def run_dnsgen_and_massdns(target, massdns_resolvers):
    ''' Guess additional subdomains with dnsgen | massdns '''
    print_bold_green("Guess additional subdomains with dnsgen | massdns")

    combined_domain_file = target + "/" + target + ".combined.txt"
    output_file = target + "/" + target + ".massdns.txt"

    if not os.path.exists(output_file):
        cmdstring = "cat " + combined_domain_file + " | dnsgen - | massdns -r " + massdns_resolvers + " -t A -o S -w " + output_file
        os.system(cmdstring)
    else:
        print_yellow("Previous dnsgen | massdns results exist. Skipping.")
    count_results('dnsgen | massdns', output_file)

def resolve_subdomains(target):
    ''' Clean up the verified massdns results '''
    print_bold_green("Resolving the subdomains")
    output_file = target + "/" + target + ".resolved.txt"
    cmdstring = "sort " + target + "/" + target + ".massdns.txt | awk '{print $1}' | sed 's/\.$//' | uniq > " + output_file
    os.system(cmdstring)
    count_results('Resolved Subdomains', output_file)

def remove_wildcard_domains(target, infile, outfile):
    ''' Removed wildcard domains from the list '''
    print_bold_green("Removing wildcard domains")
    if not os.path.exists(target + "/" + outfile):
        cmdstring = "wildcheck -i " + target + "/" + target + ".resolved.txt -t 100 -p | grep non-wildcard | cut -d ' ' -f3 > " + target + "/" + outfile
        os.system(cmdstring)
    else:
        print_yellow("Previous wildcheck results exist. Skipping.")
    count_results('Non-wildcard domains', target + "/" + outfile)

def find_web_servers(target, infile, outfile):
    ''' Probe domains for http/https servers'''
    print_bold_green("Probing for HTTP/HTTPS servers")
    if not os.path.exists(target + "/" + outfile):
        cmdstring = "cat " + target + "/" + infile + " | httprobe -c 100 | sed 's/https\?:\/\///' | sort | uniq > " + target + "/" + outfile
        os.system(cmdstring)
    else:
        print_yellow("Previous httprobe results exist. Skipping.")
    count_results('HTTP/HTTPS servers found', target + "/" + outfile)

def run_hakcrawler(target, infile, outfile):
    ''' Use hakcrawler to extract a list of endpoints from a file of domain names '''
    print_bold_green("Crawling HTTP/HTTPS servers for urls")
    if not os.path.exists(target + "/" + outfile):
        with open(target + "/" + infile) as f:
            http_servers = [line.rstrip() for line in f]
        for server in http_servers:
            print_grey(server)
            cmdstring = "hakrawler -url " + server + " -plain >> " + target + "/urls.raw.txt"
            os.system(cmdstring)
        cmdstring = "cat " + target + "/urls.raw.txt | sort | uniq > " + target + "/" + outfile
        os.system(cmdstring)
    else:
        print_yellow("Previous hakcrawler results exist. Skipping.")
    count_results('Links found', target + "/" + outfile)

def show_dalfox_results(infile):
    ''' Show the results of the dalfox scan '''
    warning_count = 0
    vulnerability_count = 0
    with open(infile, 'r') as f:
        for line in f:
            if "[W]" in line: warning_count += 1
            if "[V]" in line: vulnerability_count += 1
    print_green("XSS Results: " + str(warning_count) + " warnings, " + 
                str(vulnerability_count) + " vulnerabilities")

def run_dalfox(target, infile, outfile):
    ''' Look for XSS '''
    print_bold_green("Looking for XSS") # should this be red?
    if not os.path.exists(target + "/" + outfile):
        cmdstring = "cat " + target + "/urls.txt | dalfox pipe -o " + target + "/" + outfile
        os.system(cmdstring)
    else:
        print_yellow("Previous dalfox results exist. Skipping")
    show_dalfox_results(target + "/" + outfile)




def print_results_summary(target):
    print_bold_green("Summary of results")
    count_results('Amass', target + "/" + target + ".amass.txt")
    count_results('Subfinder', target + "/" + target + ".subfinder.txt")
    count_results('DNSBuffer', target + "/" + target + ".bufferover.txt")
    count_results('Combined Amass, Subfinder & dnsbuffer', target + "/" + target + ".combined.txt")
    count_results('dnsgen | massdns', target + "/" + target + ".massdns.txt")
    count_results('Resolved Subdomains', target + "/" + target + ".resolved.txt")
    count_results('Non-wildcard domains', target + "/" + "subdomains.non-wildcard.txt")
    count_results('HTTP/HTTPS servers found', target + "/" + "responding_http_servers.txt")
    count_results('Links found', target + "/" + "urls.txt")
    show_dalfox_results(target + "/xss.results.txt")


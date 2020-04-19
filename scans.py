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
    if os.path.exists(output_file):
        print_yellow("Moving previous amass results to " + output_file + ".bak")
        cmdstring = "mv " + output_file + " " + output_file + ".bak"
        os.system(cmdstring)
    if os.path.exists(amass_config):
        print_green("Using Amass config " + amass_config)
        cmdstring = "amass enum -config " + amass_config + " -brute -d " + target + " -o " + \
                    target + "/" + target + ".amass.txt"
    else:
        print_grey("Not using config.ini")
        cmdstring = "amass enum -brute -d " + target + " -o " + output_file
    os.system(cmdstring)
    count_results('Amass', output_file)
    # need to define and add -min-for-recursive 3
    # abort script if amass exits

def run_assetfinder(target, FB_APP_ID, FB_APP_SECRET, VT_API_KEY, SPYSE_API_TOKEN):
    ''' Runs Assetfinder after exporting environment variables '''
    print_bold_green("Running Assetfinder to find sub-domains")

    if FB_APP_ID: os.environ["FB_APP_ID"] = FB_APP_ID
    if FB_APP_SECRET: os.environ["FB_APP_SECRET"] = FB_APP_SECRET
    if VT_API_KEY: os.environ["VT_API_KEY"] = VT_API_KEY
    if SPYSE_API_TOKEN: os.environ["SPYSE_API_TOKEN"] = SPYSE_API_TOKEN

    output_file = target + "/" + target + ".assetfinder.txt"
    if os.path.exists(output_file):
        print_yellow("Moving previous assetfinder results to " + output_file + ".bak")
        cmdstring = "mv " + output_file + " " + output_file + ".bak"
        os.system(cmdstring)
    cmdstring = "assetfinder -subs-only " + target + " > " + output_file
    os.system(cmdstring)
    count_results('Assetfinder', output_file)

def run_subfinder(target):
    ''' Runs Subfinder to find subdomains '''
    print_bold_green("Running Subfinder to find sub-domains")

    output_file = target + "/" + target + ".subfinder.txt"
    cmdstring = "subfinder -d " + target + " -o " + output_file
    os.system(cmdstring)
    count_results('Subfinder', output_file)

def run_dnsbuffer(target):
    ''' Gets subdomains from Rapid7 '''
    print_bold_green("Running DNS Buffer to find sub-domains")

    output_file = target + "/" + target + ".bufferover.txt"
    cmdstring = "curl -s https://dns.bufferover.run/dns?q=." + target + " | jq -r .FDNS_A[] | " \
                "cut -d',' -f2 > " + output_file
    os.system(cmdstring)
    count_results('DNSBuffer', output_file)

def combine_subdomain_results(target):
    ''' Combine all subdomain tool results and remove duplicates '''
    print_bold_green("Combining subdomain results")

    output_file = target + "/" + target + ".combined.txt"
    cmdstring = "sort " + target + "/*.txt | uniq > " + output_file
    os.system(cmdstring)
    count_results('Combined', output_file)

def run_dnsgen_and_massdns(target, massdns_resolvers):
    ''' Guess additional subdomains with dnsgen | massdns '''
    print_bold_green("Guess additional subdomains with dnsgen | massdns")

    combined_domain_file = target + "/" + target + ".combined.txt"
    output_file = target + "/" + target + ".massdns.txt"
    cmdstring = "cat " + combined_domain_file + " | dnsgen - | massdns -r " + massdns_resolvers + " -t A -o S -w " + output_file
    os.system(cmdstring)
    count_results('dnsgen | massdns', output_file)

def finalize_subdomain_results(target):
    ''' Clean up the verified massdns results '''
    print_bold_green("Cleaning up subdomain results")
    output_file = target + "/" + target + ".final.txt"
    cmdstring = "sort " + target + "/" + target +".massdns.txt | awk '{print $1}' | sed 's/\.$//' | uniq > " + output_file
    os.system(cmdstring)
    count_results('Final Subdomains', output_file)


def print_results_summary(target):
    print_bold_green("Summary of results")
    count_results('Amass', target + "/" + target + ".amass.txt")
    count_results('Subfinder', target + "/" + target + ".subfinder.txt")
    count_results('DNSBuffer', target + "/" + target + ".bufferover.txt")
    count_results('Combined Amass, Subfinder & dnsbuffer', target + "/" + target + ".combined.txt")
    count_results('dnsgen | massdns', target + "/" + target + ".massdns.txt")
    count_results('Final Subdomains', target + "/" + target + ".final.txt")
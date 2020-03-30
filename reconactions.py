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

    if FB_APP_ID: os.system('export FB_APP_ID=' + FB_APP_ID)
    if FB_APP_SECRET: os.system('export FB_APP_SECRET=' + FB_APP_SECRET)
    if VT_API_KEY: os.system('export VT_API_KEY=' + VT_API_KEY)
    if SPYSE_API_TOKEN: os.system('export SPYSE_API_TOKEN=' + SPYSE_API_TOKEN)

    output_file = target + "/" + target + ".assetfinder.txt"
    if os.path.exists(output_file):
        print_yellow("Moving previous amass results to " + output_file + ".bak")
        cmdstring = "mv " + output_file + " " + output_file + ".bak"
        os.system(cmdstring)
    cmdstring = "assetfinder -subs-only " + target + " > " + output_file
    os.system(cmdstring)
    count_results('Assetfinder', output_file)

def run_dnsbuffer(target):
    ''' Gets subdomains from Rapid7 '''
    print_bold_green("Running Assetfinder to find sub-domains")

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

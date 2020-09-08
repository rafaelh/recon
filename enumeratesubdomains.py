import apt
import os
import sys
from common import *


def run_amass(target, amass_config, outfile):
    ''' Runs amass with the specified config file '''
    print_bold_green("Running Amass to find sub-domains")

    if not os.path.exists(target + "/" + outfile):
        if os.path.exists(amass_config):
            print_green("Using Amass config " + amass_config)
            cmdstring = "amass enum -config " + amass_config + " -brute -d " + target + " -o " + \
                        target + "/" + outfile
        else:
            print_red("Not using config.ini")
            cmdstring = "amass enum -brute -d " + target + " -o " + target + "/" + outfile
        os.system(cmdstring)
    else:
        print_yellow("Previous amass results exist. Skipping.")

def run_assetfinder(target, FB_APP_ID, FB_APP_SECRET, VT_API_KEY, SPYSE_API_TOKEN, outfile):
    ''' Runs Assetfinder after exporting environment variables '''
    print_bold_green("Running Assetfinder to find sub-domains")

    if not os.path.exists(target + "/" + outfile):
        if FB_APP_ID: os.environ["FB_APP_ID"] = FB_APP_ID
        if FB_APP_SECRET: os.environ["FB_APP_SECRET"] = FB_APP_SECRET
        if VT_API_KEY: os.environ["VT_API_KEY"] = VT_API_KEY
        if SPYSE_API_TOKEN: os.environ["SPYSE_API_TOKEN"] = SPYSE_API_TOKEN
        cmdstring = "assetfinder -subs-only " + target + " > " + target + "/" + outfile
        os.system(cmdstring)
    else:
        print_yellow("Previous Assetfinder results exist. Skipping.")

def run_subfinder(target, outfile):
    ''' Runs Subfinder to find subdomains '''
    print_bold_green("Running Subfinder to find sub-domains")

    if not os.path.exists(target + "/" + outfile):
        cmdstring = "subfinder -d " + target + " -o " + target + "/" + outfile
        os.system(cmdstring)
    else:
        print_yellow("Previous Subfinder results exist. Skipping.")

def run_dnsbuffer(target, outfile):
    ''' Gets subdomains from Rapid7 '''
    print_bold_green("Running DNS Buffer to find sub-domains")

    if not os.path.exists(target + "/" + outfile):
        cmdstring = "curl -s https://dns.bufferover.run/dns?q=." + target + " | jq -r .FDNS_A[] | " \
                    "cut -d',' -f2 > " + target + "/" + outfile
        os.system(cmdstring)
    else:
        print_yellow("Previous dnsbuffer results exist. Skipping.")

def run_massdns(target, massdns_resolvers, infile, outfile):
    ''' Attempt resolution of the subdomains '''
    print_bold_green("Resolve the subdomains")

    if not os.path.exists(target + "/" + outfile):
        cmdstring = "cat " + target + "/" + infile + " | massdns -r " + massdns_resolvers + " -t A -o S | awk '{print $1}' | sed 's/\.$//' | uniq > " + target + "/" + outfile
        os.system(cmdstring)
    else:
        print_yellow("Previous massdns results exist. Skipping.")

def run_dnsgen_and_massdns(target, massdns_resolvers, infile, massdns_output, outfile):
    ''' Guess additional subdomains with dnsgen | massdns '''
    print_bold_green("Guess additional subdomains with dnsgen | massdns")

    if not os.path.exists(target + "/" + outfile):
        cmdstring = "cat " + target + "/" + infile + " | dnsgen - | massdns -r " + \
                    massdns_resolvers + " -t A -o S -w " + target + "/" + massdns_output
        os.system(cmdstring)
        cmdstring = "cat " + target + "/" + massdns_output + \
                    " | awk '{print $1}' | sed 's/\.$//' | uniq > " + target + "/" + outfile
        os.system(cmdstring)
    else:
        print_yellow("Previous dnsgen | massdns results exist. Skipping.")

def remove_wildcard_domains(target, infile, outfile):
    ''' Removed wildcard domains from the list '''
    print_bold_green("Removing wildcard domains")
    if not os.path.exists(target + "/" + outfile):
        cmdstring = "wildcheck -i " + target + "/" + infile + \
                    " -t 100 -p | grep non-wildcard | cut -d ' ' -f3 > " + target + "/" + outfile
        os.system(cmdstring)
    else:
        print_yellow("Previous wildcheck results exist. Skipping.")

def find_web_servers(target, infile, outfile):
    ''' Probe domains for http/https servers'''
    print_bold_green("Probing for HTTP/HTTPS servers")
    if not os.path.exists(target + "/" + outfile):
        cmdstring = "cat " + target + "/" + infile + " | httprobe -c 100 | sed 's/https\?:\/\///' | sort | uniq > " + target + "/" + outfile
        os.system(cmdstring)
        cmdstring = "echo " + target + " >> " + target + "/" + outfile
        os.system(cmdstring)
    else:
        print_yellow("Previous httprobe results exist. Skipping.")

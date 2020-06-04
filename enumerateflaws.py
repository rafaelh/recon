import os
import sys
from common import *

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

def look_for_xss(xsshunter_domain, custom_xss_payloads, target, infile, outfile):
    ''' Look for XSS '''
    print_bold_green("Looking for XSS")
    if not os.path.exists(target + "/" + outfile):
        cmdstring = "cat " + target + "/" + infile + " | dalfox pipe --multicast -o " + target + "/" + outfile
        if xsshunter_domain: cmdstring += " -b " + xsshunter_domain
        if custom_xss_payloads: cmdstring += " --custom-payload " + custom_xss_payloads
        os.system(cmdstring)
    else:
        print_yellow("Previous dalfox results exist. Skipping.")
    show_dalfox_results(target + "/" + outfile)

def look_for_sqli(target, infile, outfile):
    ''' Look for SQLi '''
    print_bold_green("Looking for SQLi")
    if not os.path.exists(target + "/" + outfile):
        with open(target + "/" + infile, 'r') as rawlinksfile:
            lines = 0
            count = 0
            for line in rawlinksfile: lines += 1
            for line in rawlinksfile:
                print_green("Testing " + count + "/" + lines + " for SQLi")
                cmdstring = "dsss.py -u " + line + "/" + infile + " >> " + target + "/" + outfile
                os.system(cmdstring)
    else:
        print_yellow("Previous SQLi results exist. Skipping.")
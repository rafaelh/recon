import os
import sys
import urllib.request
from common import *


def run_hakcrawler(target, infile, outfile):
    ''' Use hakcrawler to extract a list of endpoints from a file of domain names '''
    print_message("green", "Crawling HTTP/HTTPS servers for urls")
    if not os.path.exists(target + "/" + outfile):
        with open(target + "/" + infile) as f:
            http_servers = [line.rstrip() for line in f]
        for server in http_servers:
            print_yellow(server)
            cmdstring = "hakrawler -url " + server + " -plain >> " + target + "/" + outfile
            os.system(cmdstring)
    else:
        print_yellow("Previous hakcrawler results exist. Skipping.")

def run_getallurls(target, outfile):
    ''' Gather URLs from a variety of sources '''
    print_bold_green("Getting known links from alienvault, wayback and common crawl")
    if not os.path.exists(target + "/" + outfile):
        cmdstring = "echo https://" + target + " | gau -subs > " + target + "/" + outfile
        os.system(cmdstring)
    else:
        print_yellow("Previous getallurls results exist. Skipping.")

def find_injection_points(target, infile, outfile):
    ''' Extract endpoints more likely to yield reflected XSS from a file '''
    print_bold_green("Extracting endpoints to test for XSS")
    if not os.path.exists(target + "/" + outfile):
        cmdstring = "cat " + target + "/" + infile + " | grep \"=\" | " + \
                    "egrep -iv \".(jpg|jpeg|git|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)\" | " + \
                    "qsreplace -a > " + target + "/" + outfile
        os.system(cmdstring)
    else:
        print_yellow("Previous xss injection point results exist. Skipping.")

# This is where the error is (down)
# checking in & outfiles should be extracted out into it's own function. DRY.

def validate_links(target, responsecode, infile, outfile):
    ''' Check the response code of links from a file '''
    print_message("green", "Checking which links return a " + str(responsecode) + " response code")
    if not os.path.exists(target + "/" + outfile):
        try:
            with open(target + "/" + infile, 'r') as rawlinksfile:
                lines = 0
                count = 0
                for line in rawlinksfile: lines += 1
                print_message("grey", "Links to check: " + str(lines))
                for line in rawlinksfile:
                    count += 1
                    try:
                        if urllib.request.urlopen(line).getcode() == responsecode:
                            with open(target + "/" + outfile, 'a') as validatedlinksfile:
                                validatedlinksfile.write(line)
                            print_message("green", "Response " + str(responsecode) + ": " + line.rstrip("\n"))
                    except:
                        print_message("red", "Link " + count + "/" + lines + " doesn't respond as " + responsecode)
        except IOError:
            print_message("red", "Input file " + infile + " does not appear to exist.")
    else:
        print_message("yellow", "Previous link checking results exist. Skipping.")


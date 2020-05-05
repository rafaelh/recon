import os
import sys
from common import *

def count_results(tool, output_file):
    count = 0
    with open(output_file, 'r') as f:
        for line in f:
            count += 1
    print_green(tool + " total number of results: " + str(count))

def run_hakcrawler(target, infile, outfile):
    ''' Use hakcrawler to extract a list of endpoints from a file of domain names '''
    print_bold_green("Crawling HTTP/HTTPS servers for urls")
    if not os.path.exists(target + "/" + outfile):
        with open(target + "/" + infile) as f:
            http_servers = [line.rstrip() for line in f]
        for server in http_servers:
            print_grey(server)
            cmdstring = "hakrawler -url " + server + " -plain >> " + target + "/" + outfile
            os.system(cmdstring)
    else:
        print_yellow("Previous hakcrawler results exist. Skipping.")
    count_results('Links found', target + "/" + outfile)

def run_getallurls(target, outfile):
    ''' Gather URLs from a variety of sources '''
    print_bold_green("Getting known links from alienvault, wayback and common crawl")
    if not os.path.exists(target + "/" + outfile):
        cmdstring = "echo https://" + target + " | gau -subs > " + target + "/" + outfile
        os.system(cmdstring)
    else:
        print_yellow("Previous getallurls results exist. Skipping.")
    count_results('Getallurls links found', target + "/" + outfile)

def combine_url_results(target, infile1, infile2, outfile):
    ''' Combine, sort and remove duplicates from the url finding tasks '''
    print_bold_green("Combining linkfinding results")
    if not os.path.exists(target + "/" + outfile):
        cmdstring = "sort " + target + "/" + infile1 + " " + target + "/" + infile2 + \
                    " | uniq > " + target + "/" + outfile
        os.system(cmdstring)
    else:
        print_yellow("Previous combined link results exist. Skipping.")
    count_results("Combined links found", target + "/" + outfile)
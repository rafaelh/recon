#!/usr/bin/env python3
import sys
import os
#import apt <- eventually script should install it's own tools with a prompt
#import subprocess <- things that can be done in parallel should be
from reconactions import *
from reconconfig import *

def main():
    if len(sys.argv) == 1:
        print("\nUsage: recon example.com\n")
        sys.exit(1)

    run_checks(amass_config)

    print_bold_green("Running Amass to discover domains")

    print_green("Green")
    print_grey("Grey")
    print_red("Red")
    # Run amass
    # Run assetfinder
    # Run findomain
    # Run dnsbuffer
    # Run subfinder
    # remove duplicates
    # Run livehosts
    # Run GIT-Endpoints
    # Run Directory Bruteforce


if __name__ == '__main__':
    main()

'''
TODO:
Write the whole damn thing
'''
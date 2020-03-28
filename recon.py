#!/usr/bin/env python3

import os
#import apt <- eventually script should install it's own tools with a prompt
#import subprocess <- things that can be done in parallel should be
from reconactions import *
from reconconfig import *

def main():
    # Check stuff
    print_bold_green("Bold Green")
    print_green("Green")
    print_grey("Grey")
    print_yellow("Yellow")
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
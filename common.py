import os

def print_bold_green(message):
    """ Prints a message to the console prefixed with a green '>>>' """
    print("\n\033[1;32;40m>>> \033[1;37;40m" + message + "\033[0;37;0m")

def print_green(message):
    """ Prints a message to the console prefixed with a green '[*]' """
    print("[\033[0;32;40m*\033[0;37;40m] " + message + "\033[0;37;0m")

def print_yellow(message):
    """ Prints a message to the console prefixed with a yellow '[*]' """
    print("[\033[1;33;40m*\033[0;37;40m] " + message + "\033[0;37;0m")

def print_red(message):
    """ Prints a message to the console prefixed with a red '[*]' """
    print("[\033[0;31;40m*\033[0;37;40m] " + message + "\033[0;37;0m")

def combine_results(target, infile1="", infile2="", infile3="", infile4="", outfile=""):
    ''' Combine, sort and remove duplicates from the url finding tasks '''
    print_bold_green("Combining results")
    if not os.path.exists(target + "/" + outfile):
        cmdstring = "sort "
        if infile1: cmdstring += target + "/" + infile1 + " "
        if infile2: cmdstring += target + "/" + infile2 + " "
        if infile3: cmdstring += target + "/" + infile3 + " "
        if infile4: cmdstring += target + "/" + infile4 + " "
        cmdstring += " | uniq > " + target + "/" + outfile
        os.system(cmdstring)
    else:
        print_yellow("Previous combined results exist. Skipping.")
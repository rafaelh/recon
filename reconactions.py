import apt # Move with run_checks
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

def print_grey(message):
    """ Prints a message to the console prefixed with a grey '[*]' """
    print("[\033[0;37;40m*\033[0;37;40m] " + message + "\033[0;37;0m")

def print_red(message):
    """ Prints a message to the console prefixed with a red '[*]' """
    print("[\033[0;31;40m*\033[0;37;40m] " + message + "\033[0;37;0m")

# ==== May end up in a different file =================================================

def check_package(package, apt_cache):
    if not apt_cache[package].is_installed:
        print_red(package + " is required.")
        cmdstring = "sudo apt install " + package
        os.system(cmdstring)
    

def run_checks(amass_config):
    ''' Confirm that all needed tools and config is available *before* wasting any time '''
    # Confirm packages are installed
    packages_to_check = ['amass', 'gobuster']
    apt_cache = apt.Cache()
    for package in packages_to_check:
        check_package(package, apt_cache)
    
    if not os.path.exists(amass_config):
        print_yellow("Amass config not found. Results may not be as complete.")



# =====================================================================================
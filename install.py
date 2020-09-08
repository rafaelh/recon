#!/usr/bin/env python3

import os
import apt
import subprocess
import sys
from datetime import datetime

def print_message(color, message):
    """ Prints a formatted message to the console """
    if   color == "green":  print("\033[1;32m[+] \033[0;37m" + datetime.now().strftime("%H:%M:%S") + " - " + message)
    elif color == "blue":   print("\033[1;34m[i] \033[0;37m" + datetime.now().strftime("%H:%M:%S") + " - " + message)
    elif color == "yellow": print("\033[0;33m[<] \033[0;37m" + datetime.now().strftime("%H:%M:%S") + " - " + message, end="")
    elif color == "red":    print("\033[1;31m[-] \033[0;37m" + datetime.now().strftime("%H:%M:%S") + " - " + message)
    elif color == "error":  print("\033[1;31m[!] \033[0;37m" + datetime.now().strftime("%H:%M:%S") + " - " + message)
    else:                   print("\033[0;41mInvalid Format\033[0;37m " + datetime.now().strftime("%H:%M:%S") + " " + message)

def elevate_privileges():
    """ Gets sudo privileges and returns the current date """
    status = os.system("sudo date; echo")
    return status

def take_ownership(directory):
    username = os.path.expanduser("~").split('/')[2]
    cmdstring = "sudo chown " + username + ":" + username + " " + directory
    os.system(cmdstring)

def update_packages():
    """ Do a general update of the system packages """
    cmdseries = ['sudo apt update',
                 'sudo apt full-upgrade -y',
                 'sudo apt autoremove -y']
    for cmdstring in cmdseries:
        os.system(cmdstring)

def install_package(package, apt_cache):
    """ Installs a package from apt or lets you know if its present """
    if not apt_cache[package].is_installed:
        print_message("green", "Installing " + package)
        cmdstring = "sudo apt install -y " + package
        os.system(cmdstring)

def pip_package_install(pip_packages, installed_pip_packages):
    """ Install python pip package """
    for package in pip_packages:
        if not package in installed_pip_packages:
            print_message("green", "Installing pip package " + package)
            cmdstring = "sudo pip3 install --upgrade " + package
            os.system(cmdstring)

def gem_package_install(gem_packages, installed_gem_packages):
    """ Install Ruby gem package """
    for package in gem_packages:
        if not package in installed_gem_packages:
            print_message("green", "Installing gem package " + package)
            cmdstring = "sudo gem install " + package
            os.system(cmdstring)

def install_golang_module(module):
    """ Install the specified Golang module """
    modulename = module.split("/")[-1].lower()
    if not os.path.exists("/opt/" + modulename):
        print_message("green", "Installing go module " + modulename)
        cmdseries = ["sudo -E go get -u " + module,
                     "sudo ln -s /opt/" + modulename + "/bin/" + modulename + " /usr/local/bin/" \
                     + modulename]
        os.environ["GOPATH"] = "/opt/" + modulename
        for cmdstring in cmdseries:
            os.system(cmdstring)

def create_directory(directory):
    """ Checks if the specified directory exists, and creates it if not """
    if not os.path.exists(directory):
        print_message("green", "Creating directory: " + directory)
        cmdstring = "mkdir " + directory
        os.system(cmdstring)

def remove_directory(directory):
    """ Checks if the specified directory exists, and deletes it if it does """
    directory = os.getenv("HOME") + '/' + directory
    if os.path.exists(directory):
        print_message("red", "Removing directory: " + directory)
        cmdstring = "rmdir " + directory
        os.system(cmdstring)

def sync_git_repo(gitrepo, repo_collection_dir):
    """ Sync the specified git repository """
    repo_name = gitrepo.split("/")[-1].lower()
    if os.path.exists(repo_collection_dir + '/' + repo_name):
        print_message("yellow", "Syncing " + repo_name + ": ")
        sys.stdout.flush()
        cmdstring = "git -C " + repo_collection_dir + '/' + repo_name + " pull"
        os.system(cmdstring)
    else:
        print_message("green", "Cloning " + repo_name)
        cmdstring = "git clone " + gitrepo + ' ' + repo_collection_dir + '/' + repo_name
        os.system(cmdstring)

def run_scripts():
    """ Run each .sh or .py file in the scripts directory """
    script_directory = os.path.dirname(os.path.realpath(__file__)) + '/install_scripts'

    if os.path.exists(script_directory):
        scripts = sorted(os.listdir(script_directory))
        for script in scripts:
            if '.sh' or '.py' in script:
                cmdstring = script_directory + '/' + script
                os.system(cmdstring)
    else:
        print_message("error", "'scripts' directory is missing")



def main():
    ''' This script installs the requisite tools for recon. '''

    # Get sudo privileges
    if elevate_privileges(): sys.exit(1)

    # These kali packages will be installed
    packages_to_install = ['amass', 'golang', 'jq', 'python3-pip', 'chromium']

    # These python packages will be installed globally
    pip_packages = ['pipenv', 'pylint', 'dnsgen', 'stegcracker']

    # These gem packages will be installed globally
    gem_packages = []

    # These go tools will be installed globally. You will need to have the following settings in your
    # .bashrc already:
    #
    # export GOROOT=/usr/lib/go
    # export GOPATH=$HOME/go
    # export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
    golang_modules_to_install = [
                                'github.com/tomnomnom/assetfinder',
                                'github.com/projectdiscovery/subfinder/cmd/subfinder',
                                'github.com/lc/gau',
                                'github.com/theblackturtle/wildcheck',
                                'github.com/tomnomnom/httprobe',
                                'github.com/hakluke/hakrawler',
                                'github.com/tomnomnom/qsreplace',
                                'github.com/hahwul/dalfox',
                                'github.com/ffuf/ffuf',
                                'github.com/dwisiswant0/hinject'
                                ]

    # These git repositories will be synced to the 'external repo' directory
    external_tools_directory = '/opt'
    ext_repositories_to_sync = [
                                'https://github.com/Cillian-Collins/dirscraper',
                                'https://github.com/maurosoria/dirsearch'
                                ]

    # Sync the script with Github version
    print_message("blue", "Syncing 'recon' files")
    script_git_status = subprocess.Popen(["git", "-C", os.path.dirname(os.path.realpath(__file__)),
                                          "pull", "origin", "main"], stdout=subprocess.PIPE)
    script_git_status_output = script_git_status.communicate()[0]
    if "Already up to date" not in script_git_status_output.decode():
        print_message("error", "Files updated. Please run the new version.\n")
        sys.exit(1)

    # Update and upgrade apt packages
    print_message("blue", "General Update")
    update_packages()

    # Install or remove specified apt packages
    print_message("blue", "Checking installed packages")
    apt_cache = apt.Cache()
    for package in packages_to_install:
        install_package(package, apt_cache)

    # Install python modules
    print_message("blue", "Checking python modules")
    installed_pip_packages = [r.decode().split('==')[0] for r in \
        subprocess.check_output([sys.executable, '-m', 'pip', 'freeze']).split()]
    pip_package_install(pip_packages, installed_pip_packages)

    # Install gem packages
    print_message("blue", "Checking ruby gems")
    gemlist = subprocess.Popen(["gem list | awk '{ print $1 }'"], shell=True, stdout=subprocess.PIPE).stdout
    installed_gem_packages = gemlist.read().decode("utf-8").split("\n")
    gem_package_install(gem_packages, installed_gem_packages)

    # Take ownership of the external tools directory
    take_ownership(external_tools_directory)

    # Install golang tools
    print_message("blue", "Checking golang modules")
    for module in golang_modules_to_install:
        install_golang_module(module)

    # Create specified directories
    print_message("blue", "Checking directory structure")
    create_directory(external_tools_directory)
    create_directory("~/r")

    # Sync git repositories
    print_message("blue", "Syncing git repositories")
    for repo in ext_repositories_to_sync:
        sync_git_repo(repo, external_tools_directory)

    # Run *.sh and *.py files in the /scripts directory
    print_message("blue", "Running scripts")
    run_scripts()

    print("\nAll done. Ready to run.\n")


if __name__ == '__main__':
    main()

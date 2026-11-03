#!/usr/bin/env python3

import os
import shutil
import subprocess
import sys
from datetime import datetime

RECON_TOOLS_DIR = os.path.expanduser(os.getenv("RECON_TOOLS_DIR", "~/.recon-tools"))
RECON_BIN_DIR = RECON_TOOLS_DIR + "/bin"

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

def detect_package_manager():
    """ Returns 'brew' (macOS), 'apt' (Kali/Debian) or 'yay' (Arch) """
    if sys.platform == "darwin":
        return "brew"
    os_ids = []
    if os.path.exists("/etc/os-release"):
        with open("/etc/os-release") as os_release:
            for line in os_release:
                key, _, value = line.strip().partition("=")
                if key in ("ID", "ID_LIKE"):
                    os_ids += value.strip('"').split()
    if "arch" in os_ids:
        return "yay"
    if "debian" in os_ids or "kali" in os_ids:
        return "apt"
    return None

def update_packages(package_manager):
    """ Do a general update of the system packages """
    cmdseries = {'apt':  ['sudo apt update',
                          'sudo apt full-upgrade -y',
                          'sudo apt autoremove -y'],
                 'yay':  ['yay -Syu --noconfirm'],
                 'brew': ['brew update',
                          'brew upgrade']}
    for cmdstring in cmdseries[package_manager]:
        os.system(cmdstring)

def is_package_installed(package, package_manager):
    """ Checks whether a system package is installed """
    if package_manager == "apt":
        cmd = ["dpkg-query", "-W", "-f=${Status}", package]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return "ok installed" in result.stdout
    if package_manager == "yay":
        cmd = ["pacman", "-Q", package]
    elif package.startswith("--cask "):
        cmd = ["brew", "list", "--cask", package.split()[-1]]
    else:
        cmd = ["brew", "list", "--formula", package]
    return subprocess.run(cmd, capture_output=True).returncode == 0

def install_package(package, package_manager):
    """ Installs a system package or lets you know if its present """
    if not is_package_installed(package, package_manager):
        print_message("green", "Installing " + package.split()[-1])
        cmdstring = {'apt':  "sudo apt install -y " + package,
                     'yay':  "yay -S --needed --noconfirm " + package,
                     'brew': "brew install " + package}[package_manager]
        os.system(cmdstring)

def uv_tool_install(uv_tools):
    """ Install python tools into their own virtualenvs, with the binaries in RECON_BIN_DIR """
    env = dict(os.environ, UV_TOOL_DIR=RECON_TOOLS_DIR + "/uv-tools", UV_TOOL_BIN_DIR=RECON_BIN_DIR)
    tool_list = subprocess.run(["uv", "tool", "list"], capture_output=True, text=True, env=env)
    installed_tools = [line.split()[0] for line in tool_list.stdout.splitlines()
                       if line and not line.startswith("-")]
    for package in uv_tools:
        name = package.split("/")[-1].removesuffix(".git").lower()
        if name not in installed_tools:
            print_message("green", "Installing python tool " + name)
            subprocess.run(["uv", "tool", "install", package], env=env)

def gem_package_install(gem_packages, installed_gem_packages):
    """ Install Ruby gem package """
    for package in gem_packages:
        if not package in installed_gem_packages:
            print_message("green", "Installing gem package " + package)
            cmdstring = "gem install --user-install " + package
            os.system(cmdstring)

def install_golang_module(module):
    """ Install the specified Golang module into RECON_BIN_DIR """
    # The binary is named after the last path element, skipping a /vN major version suffix
    parts = module.split("/")
    modulename = parts[-2] if parts[-1][1:].isdigit() and parts[-1][0] == "v" else parts[-1]
    if not os.path.exists(RECON_BIN_DIR + "/" + modulename):
        print_message("green", "Installing go module " + modulename)
        env = dict(os.environ, GOBIN=RECON_BIN_DIR)
        subprocess.run(["go", "install", module + "@latest"], env=env)

def create_directory(directory):
    """ Checks if the specified directory exists, and creates it if not """
    directory = os.path.expanduser(directory)
    if not os.path.exists(directory):
        print_message("green", "Creating directory: " + directory)
        os.makedirs(directory)

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
        env = dict(os.environ, RECON_TOOLS_DIR=RECON_TOOLS_DIR)
        for script in scripts:
            if script.startswith('install-') and script.endswith(('.sh', '.py')):
                subprocess.run([script_directory + '/' + script], env=env)
    else:
        print_message("error", "'scripts' directory is missing")



def main():
    ''' This script installs the requisite tools for recon. '''

    package_manager = detect_package_manager()
    if package_manager is None:
        print_message("error", "Unsupported OS. Use macOS (brew), Kali (apt) or Arch (yay).")
        sys.exit(1)
    if not shutil.which(package_manager):
        print_message("error", package_manager + " is not installed.")
        sys.exit(1)

    # Get sudo privileges (Homebrew must not be run with sudo)
    if package_manager != "brew" and elevate_privileges(): sys.exit(1)

    # These system packages will be installed. Everything else goes in RECON_TOOLS_DIR.
    # amass is in the AUR on Arch, which yay handles. Homebrew's chromium cask is disabled,
    # so Chrome is used on macOS instead (needed by gowitness).
    packages_to_install = {
        'apt':  ['amass', 'golang-go', 'jq', 'uv', 'git', 'build-essential', 'curl', 'chromium'],
        'yay':  ['amass', 'go', 'jq', 'uv', 'git', 'base-devel', 'curl', 'chromium'],
        'brew': ['amass', 'go', 'jq', 'uv', 'git'],
    }[package_manager]
    if package_manager == "brew" and not os.path.exists("/Applications/Google Chrome.app"):
        packages_to_install.append('--cask google-chrome')

    # These python tools will be installed with `uv tool`, each in its own virtualenv
    uv_tools = ['pipenv', 'pylint', 'dnsgen', 'stegcracker',
                'git+https://github.com/maurosoria/dirsearch.git']

    # These gem packages will be installed for the current user
    gem_packages = []

    # These go tools will be installed with `go install`
    golang_modules_to_install = [
                                'github.com/tomnomnom/assetfinder',
                                'github.com/projectdiscovery/subfinder/v2/cmd/subfinder',
                                'github.com/lc/gau/v2/cmd/gau',
                                'github.com/theblackturtle/wildcheck',
                                'github.com/tomnomnom/httprobe',
                                'github.com/hakluke/hakrawler',
                                'github.com/tomnomnom/qsreplace',
                                'github.com/ffuf/ffuf/v2',
                                'github.com/dwisiswant0/hinject',
                                'github.com/sensepost/gowitness'
                                ]

    # These git repositories will be synced to RECON_TOOLS_DIR
    ext_repositories_to_sync = [
                                'https://github.com/Cillian-Collins/dirscraper'
                                ]

    # Sync the script with Github version
    print_message("blue", "Syncing 'recon' files")
    script_git_status = subprocess.Popen(["git", "-C", os.path.dirname(os.path.realpath(__file__)),
                                          "pull", "origin", "main"], stdout=subprocess.PIPE)
    script_git_status_output = script_git_status.communicate()[0]
    if "Already up to date" not in script_git_status_output.decode():
        print_message("error", "Files updated. Please run the new version.\n")
        sys.exit(1)

    # Update and upgrade system packages
    print_message("blue", "General Update")
    update_packages(package_manager)

    # Install specified system packages
    print_message("blue", "Checking installed packages")
    for package in packages_to_install:
        install_package(package, package_manager)

    # Create specified directories
    print_message("blue", "Checking directory structure")
    create_directory(RECON_BIN_DIR)
    create_directory("~/r")

    # Install python tools
    print_message("blue", "Checking python tools")
    uv_tool_install(uv_tools)

    # Install gem packages
    if gem_packages and shutil.which("gem"):
        print_message("blue", "Checking ruby gems")
        gemlist = subprocess.Popen(["gem list | awk '{ print $1 }'"], shell=True, stdout=subprocess.PIPE).stdout
        installed_gem_packages = gemlist.read().decode("utf-8").split("\n")
        gem_package_install(gem_packages, installed_gem_packages)

    # Install golang tools
    print_message("blue", "Checking golang modules")
    for module in golang_modules_to_install:
        install_golang_module(module)

    # Sync git repositories
    print_message("blue", "Syncing git repositories")
    for repo in ext_repositories_to_sync:
        sync_git_repo(repo, RECON_TOOLS_DIR)

    # Run install-* scripts in the install_scripts directory
    print_message("blue", "Running scripts")
    run_scripts()

    if RECON_BIN_DIR not in os.environ.get("PATH", "").split(os.pathsep):
        print_message("blue", "Add the tools to your PATH in ~/.zshrc or ~/.bashrc:")
        print('    export PATH="$HOME/.recon-tools/bin:$PATH"')

    print("\nAll done. Ready to run.\n")


if __name__ == '__main__':
    main()

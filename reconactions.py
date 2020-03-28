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

def run_checks():
    ''' Confirm that all needed tools and config is available *before* wasting any time '''
    # check amass is installed
    # check amass_config_exists, warn otherwise


# =====================================================================================
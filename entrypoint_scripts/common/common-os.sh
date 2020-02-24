# DefectDojo install 'library' to handle determining which OS the installer is being run on
#  

find_linux_distro() {
	# Determine Linux Distro
	# Based on https://unix.stackexchange.com/questions/6345/how-can-i-get-distribution-name-and-version-number-in-a-simple-shell-script
	if [ -f /etc/os-release ]; then
	    # freedesktop.org and systemd
	    . /etc/os-release
	    OS=$NAME
	    VER=$VERSION_ID
	elif type lsb_release >/dev/null 2>&1; then
	    # linuxbase.org
	    OS=$(lsb_release -si)
	    VER=$(lsb_release -sr)
	elif [ -f /etc/lsb-release ]; then
	    # For some versions of Debian/Ubuntu without lsb_release command
	    . /etc/lsb-release
	    OS=$DISTRIB_ID
	    VER=$DISTRIB_RELEASE
	elif [ -f /etc/debian_version ]; then
	    # Older Debian/Ubuntu/etc.
	    OS=Debian
	    VER=$(cat /etc/debian_version)
	elif [ -f /etc/SuSe-release ]; then
	    # Older SuSE/etc.
	    echo "  ERROR: Unsupported Linux distro - exiting."
	    exit 1
	elif [ -f /etc/redhat-release ]; then
	    # Older Red Hat, CentOS, etc.
	    echo "  ERROR: Unsupported Linux distro - exiting."
	    exit 1
	else
	    # Fall back to uname, e.g. "Linux <version>", also works for BSD, etc.
	    OS=$(uname -s)
	    VER=$(uname -r)
	    echo "  ERROR: Unsupported Linux distro - exiting."
	    exit 1
	fi
	
	INSTALL_DISTRO=$OS
	INSTALL_OS_VER=$VER
}

check_install_os() {
	#  Determine OS
	# based on https://stackoverflow.com/questions/394230/how-to-detect-the-os-from-a-bash-script
	echo "Inside check install os"
	if [[ "$OSTYPE" == "linux-gnu" ]]; then
	    # Liux
	    echo "Install on Linux"
	    INSTALL_OS="linux-gnu"
	    find_linux_distro
	elif [[ "$OSTYPE" == "darwin"* ]]; then
	    # Mac OSX
	    echo "Install on Mac OSX"
	    INSTALL_OS="darwin"
	    # From https://www.cyberciti.biz/faq/mac-osx-find-tell-operating-system-version-from-bash-prompt/
	    INSTALL_DISTRO=`sw_vers -productName`
	    INSTALL_OS_VER=`sw_vers -productVersion`
	elif [[ "$OSTYPE" == "cygwin" ]]; then
	    # POSIX compatibility layer and Linux environment emulation for Windows
	    echo "  ERROR: Windows isn't currently supported"
	    exit 1
	elif [[ "$OSTYPE" == "msys" ]]; then
	    # Lightweight shell and GNU utilities compiled for Windows (part of MinGW)
	    echo "  ERROR: MinGW isn't currently supported"
	    exit 1
	elif [[ "$OSTYPE" == "win32" ]]; then
	    # I'm not sure this can happen.
	    echo "  ERROR: Windows isn't currently supported"
	    exit 1
	elif [[ "$OSTYPE" == "freebsd"* ]]; then
	    # FreeBSD
	    echo "  ERROR: FreeBSD isn't currently supported"
	    exit 1
	else
	    # Unable to determine OS, exit with error
	    echo "  ERROR: Unable to determine OS type, exiting."
	    exit 1
	fi
}

bootstrap_install() {
	echo "Inside bootstrap install"
	
	# Check for proper permissions - either root or sudo access
	if [[ $EUID -ne 0 ]]; then
	   # Install user isn't root,  check for sudo privileges
	   echo "  Checking for sudo access, you may be prompted for your password"
       sudo -v 2>/dev/null
       SUDO_CHECK=`sudo -v | wc -l | awk '{$1=$1; print}'`
       if [ "$SUDO_CHECK" = 0 ] ; then
         echo "  Install user has sudo access"
       else
         echo "  ERROR: Install user needs sudo access or to be root, quitting"
         exit 1
       fi
	else
	  echo "  Install user is root, sudo not required"
	fi
	
	# Install any programs needed by the installer
	case $INSTALL_DISTRO in
	    "Ubuntu" | "Linux Mint")
	    echo "  Bootstapping Ubuntu"
	    echo "  Updating package list"
	    DEBIAN_FRONTEND=noninteractive apt update
	    echo "  Updating $INSTALL_DISTRO packages"
	    DEBIAN_FRONTEND=noninteractive apt -y upgrade
	    echo "  Installing packages needed for the installer"
	    DEBIAN_FRONTEND=noninteractive apt -y install curl sudo python expect wget git gnupg2
	    ;;
	    "centos")
	    echo "Bootstapping CentOS"
	    echo "  TBD: Pre-reqs for CentOS"
	    ;;
	    *)
	    echo "    Error: Unsupported OS"
	    exit 1
	    ;;
	esac
}

check_python_version() {
	# 
	echo "Inside check python version"
	# Detect Python version
    PYV=`python -c "import sys;t='{v[0]}.{v[1]}'.format(v=list(sys.version_info[:2]));sys.stdout.write(t)";`
    if [[ "$PYV"<"2.7" ]]; then
        echo "ERROR: DefectDojo requires Python 2.7+"
        exit 1;
    else
        echo "Python version 2.7+ found, installation can continue"
    fi
}


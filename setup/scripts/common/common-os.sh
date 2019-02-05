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
        echo ""
        echo "##############################################################################"
        echo "#  ERROR: Unsupported Linux distro - older SUSE - exiting.                   #"
        echo "##############################################################################"
        echo ""
	    exit 1
	elif [ -f /etc/redhat-release ]; then
	    # Older Red Hat, CentOS, etc.
        echo ""
        echo "##############################################################################"
        echo "#  ERROR: Unsupported Linux distro - older RedHat/CentOS - exiting.          #"
        echo "##############################################################################"
        echo ""
	    exit 1
	else
	    # Fall back to uname, e.g. "Linux <version>", also works for BSD, etc.
	    OS=$(uname -s)
	    VER=$(uname -r)
        echo ""
        echo "##############################################################################"
        echo "#  ERROR: Unsupported Linux distro - unknown distro - exiting.               #"
        echo "##############################################################################"
        echo ""
	    exit 1
	fi

	INSTALL_DISTRO=$OS
	INSTALL_OS_VER=$VER

    echo "=============================================================================="
    echo "  Linux install on $OS version $VER"
    echo "=============================================================================="
    echo ""
}

check_install_os() {
	#  Determine OS
	# based on https://stackoverflow.com/questions/394230/how-to-detect-the-os-from-a-bash-script
    echo "=============================================================================="
    echo "  Determining installation OS"
    echo "=============================================================================="
    echo ""
	if [[ "$OSTYPE" == "linux-gnu" ]]; then
	    # Liux
        echo "=============================================================================="
        echo "  OS type for install is Linux"
        echo "=============================================================================="
        echo ""
	    INSTALL_OS="linux-gnu"
	    find_linux_distro
	elif [[ "$OSTYPE" == "darwin"* ]]; then
	    # Mac OSX
        echo "=============================================================================="
        echo "  OS type for install is OS X/Darwin"
        echo "=============================================================================="
        echo ""
	    INSTALL_OS="darwin"
	    # From https://www.cyberciti.biz/faq/mac-osx-find-tell-operating-system-version-from-bash-prompt/
	    INSTALL_DISTRO=`sw_vers -productName`
	    INSTALL_OS_VER=`sw_vers -productVersion`
	elif [[ "$OSTYPE" == "cygwin" ]]; then
	    # POSIX compatibility layer and Linux environment emulation for Windows
        echo "##############################################################################"
        echo "#  ERROR: Cygwin on Windows found - not a supported install target           #"
        echo "##############################################################################"
        echo ""
	    exit 1
	elif [[ "$OSTYPE" == "msys" ]]; then
	    # Lightweight shell and GNU utilities compiled for Windows (part of MinGW)
        echo "##############################################################################"
        echo "#  ERROR: MinGW on Windows found - not a supported install target            #"
        echo "##############################################################################"
        echo ""
	    exit 1
	elif [[ "$OSTYPE" == "win32" ]]; then
	    # I'm not sure this can happen.
        echo "##############################################################################"
        echo "#  ERROR: Windows detected - not a supported install target                  #"
        echo "##############################################################################"
        echo ""
	    exit 1
	elif [[ "$OSTYPE" == "freebsd"* ]]; then
	    # FreeBSD
        echo "##############################################################################"
        echo "#  ERROR: FredBSD detected - not a supported install target                  #"
        echo "##############################################################################"
        echo ""
	    exit 1
	else
	    # Unable to determine OS, exit with error
        echo "##############################################################################"
        echo "#  ERROR: Unable to determine OS type - exiting install                      #"
        echo "##############################################################################"
        echo ""
	    exit 1
	fi
}

bootstrap_install() {
    echo "=============================================================================="
    echo "  Bootstrapping required installer dependencies"
    echo "=============================================================================="
    echo ""

	# Check for proper permissions - either root or sudo access
	if [[ $EUID -ne 0 ]]; then
	    # Install user isn't root,  check for sudo privileges
        echo "=============================================================================="
        echo "  Checking for sudo access - you may be prompted for a password"
        echo "=============================================================================="
        echo ""
        sudo -v 2>/dev/null
        SUDO_CHECK=`sudo -v | wc -l`
        if [ "$SUDO_CHECK" = 0 ] ; then
            echo "=============================================================================="
            echo "  Sufficient priveleges found, continuing installation"
            echo "=============================================================================="
            echo ""
        else
            echo "##############################################################################"
            echo "#  root or sudo access required for installer - exiting                      #"
            echo "##############################################################################"
            echo ""
            exit 1
        fi
	else
        echo "=============================================================================="
        echo "  Install user is root, sudo access not required, continuing installation"
        echo "=============================================================================="
        echo ""
	fi

	# Install any programs needed by the installer
	case $INSTALL_DISTRO in
	    "Ubuntu")
        echo "=============================================================================="
        echo "  Bootstrapping $INSTALL_DISTRO - updating and packages used by the installer"
        echo "=============================================================================="
        echo ""
	    DEBIAN_FRONTEND=noninteractive apt update
	    DEBIAN_FRONTEND=noninteractive apt -y upgrade
	    DEBIAN_FRONTEND=noninteractive apt -y install curl sudo python3 expect wget git gnupg2
	    ;;
	    "centos")
        echo "=============================================================================="
        echo "  Bootstrapping $INSTALL_DISTRO - updating and packages used by the installer"
        echo "=============================================================================="
        echo ""
	    echo "  TBD: Pre-reqs for CentOS - exiting. Sorry"
        exit 1
	    ;;
	    *)
        echo "##############################################################################"
        echo "#  ERROR: Unknown or NIY OS - exiting                                        #"
        echo "##############################################################################"
        echo ""
	    exit 1
	    ;;
	esac
}

check_python_version() {
    echo ""
    echo "=============================================================================="
    echo "  Checking that Python 3+ is installed"
    echo "=============================================================================="
    echo ""
    if command -v python3 &>/dev/null; then
        PYTHON_VER=`python3 -V`
        echo "=============================================================================="
        echo "  $PYTHON_VER found, continuing install"
        echo "=============================================================================="
        echo ""
    else
        echo "##############################################################################"
        echo "#  ERROR: Python 3 required - exiting                                        #"
        echo "##############################################################################"
        echo ""
    fi
}


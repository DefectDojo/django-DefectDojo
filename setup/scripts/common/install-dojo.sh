# DefectDojo install 'library' to handle installing DefectDojo across multiple install targets
# 

# Case statement on OS - move OS specific install code into separate included files
install_dojo() {
	OS_LIBS="$SETUP_BASE/scripts/os"
	echo "=============================================================================="
	echo "  Starting the install of Defect Dojo"
	echo "=============================================================================="
	echo ""
	case $INSTALL_OS in
	    "linux-gnu")
        echo "=============================================================================="
        echo "  Linux install target"
        echo "=============================================================================="
        echo ""
	    . "$OS_LIBS/linux.sh"
	    install_linux
	    ;;
	    "darwin")
        echo "=============================================================================="
        echo "  Mac OS X install target"
        echo "=============================================================================="
        echo ""
	    echo "  TODO: Installer code for Mac OS X"
        exit 1
	    ;;
	    *)
        echo "##############################################################################"
        echo "#  ERROR: Unknown or NIY install target - exiting                            #"
        echo "##############################################################################"
        echo ""
	    echo "    Error: Unsupported OS"
	    exit 1
	    ;;
	esac
}

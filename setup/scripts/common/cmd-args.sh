# DefectDojo install 'library' to handle command-line arguments
#

function help() {
    echo "Usage: $0 [OPTION]..."
    echo ""
    echo "Install DefectDojo in an interactive (default) or non-interactive method"
    echo ""
    echo "Options:"
    echo "  -h or --help             Display this help message and exit with a status code of 0"
    echo "  -n or --non-interactive  Run install non-interactivity e.g. for Dockerfiles or automation"
    echo ""
    echo "Note: No options are required, all are optional"
}

function welcome_msg() {
    echo ""
 	echo "        ____       ____          __     ____          _      "
	echo "       / __ \___  / __/__  _____/ /_   / __ \____    (_)___  "
	echo "      / / / / _ \/ /_/ _ \/ ___/ __/  / / / / __ \  / / __ \ "
	echo "     / /_/ /  __/ __/  __/ /__/ /_   / /_/ / /_/ / / / /_/ / "
	echo "    /_____/\___/_/  \___/\___/\__/  /_____/\____/_/ /\____/  "
	echo "                                               /___/         "
    echo ""
	echo " Welcome to DefectDojo! This is a quick script to get you up and running."
	echo " For more info on how ${0##*/} does an install, see:"
	echo "   https://github.com/DefectDojo/django-DefectDojo/tree/master/setup"
	echo ""
}

function read_cmd_args() {
    # Check the arguments sent to setup.bash
    # from: https://stackoverflow.com/questions/192249/how-do-i-parse-command-line-arguments-in-bash Method #1
    for i in ${BASH_ARGV[*]}
	  do
	    case $i in
	      -h|--help)
	      help
	      exit 0
	      ;;
	      -n|--non-interactive)
	      PROMPT=false
	      ;;
	    esac
	done

    welcome_msg
}

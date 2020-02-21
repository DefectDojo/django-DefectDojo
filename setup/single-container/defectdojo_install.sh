#!/bin/bash

# The aim of this script is to create usable image for running DefectDojo application
# over existing artifacts:
# * database files
# * application files
# Author: Alexander Tyutin <alexander@tyutin.net> https://github.com/AlexanderTyutin


# Fill variables values from input parameters
for i in "$@"
do
        case $i in
		-imagename=*)
		IMAGENAME="${i#*=}"
		shift
		;;
                -appdir=*)
                APPDIR="${i#*=}"
                shift
                ;;
                -dbdir=*)
                DBDIR="${i#*=}"
                shift
                ;;
		-port=*)
		PORT="${i#*=}"
		shift
		;;
        esac
done
# -------------------------------------------

# Check variables values and corresponding directories
[ -z "$IMAGENAME" ] && echo "<imagename> parameter is not set. Exiting." && exit

[ -z "$APPDIR" ] && echo "<appdir> parameter is not set. Exiting." && exit
if [ ! -d $APPDIR ]; then
	echo "Application directory <appdir> does not exist. Exiting."
	exit
fi

[ -z "$DBDIR" ] && echo "<dbdir> parameter is not set. Exiting." && exit
if [ ! -d $DBDIR ]; then
        echo "Database directory <dbdir> does not exist. Exiting." 
        exit
fi

[ -z "$PORT" ] && echo "<port> parameter is not set. Exiting." && exit
# --------------------------------------------

# Run image building and application setup
# to get artifacts: application and ready database

docker build -t $IMAGENAME -f Dockerfile.update . && docker run -it --name $IMAGENAME -v $DBDIR:/var/lib/mysql -v $APPDIR:/opt/dojo -p $PORT:8000 $IMAGENAME
# ------------------------------------------------

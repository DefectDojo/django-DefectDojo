## END OF LIFE ##
This install method is end of life and has been removed from the codebase. The documentation below is only here for future reference and may be removed at any point in time.

## Documentation on setup.bash

The bash script setup.bash was created to automate installation of Defect Dojo and allow for the following install situations to be automated:

### Supported Installs

* Single Server - simplest DefectDojo install where DefectDojo, Dojo dependencies and 3rd party services are installed on a single server. [default install]
* Dev Install - install for local development where a Single Server install is run with credentials and other passwords set to known values.
* Stand-alone Server - install DefectDojo & Dojo dependencies only where 3rd party services (database) is running on other infrastructure.
* ? Docker Single Server - a Single Server install where DefectDojo, Dojo dependencies and 3rd party services are installed in a single container
* ? Docker Stand-alone - a Stand-alone Server install DefectDojo & Dojo dependencies only are installed in a single container.

Note: Cloning the DefectDojo repo and running ./setup.bash does a single server interactive install.  Doing other install methods requires setting configuration values and/or using command-line options.

### TDB install situations

* Docker Dev Install - a dev install that uses docker + a mounted local directory structure to isolate dojo code from the rest of the run-time.
* Fronted Dojo Installs - a install of DefectDojo where a separate HTTP server answers the initial requests for DefectDojo such as using Nginx upstream of DefectDojo

### Assumptions

All installs make these assumption:

* DefectDojo will be run in a virtualenv
* All installs support an interactive and non-interactive install methods
* All installation configuration lives in ./dojo/settings/template-env
  * Running setup.bash without editing template-env assumes a single-server install.
  * Running setup.bash without editing template-env non-interactively assumes a single-server install with MySQL
* Any install configuration variable can be overridden by setting an environmental variable
* One of the following Operating Systems is used as the base for the install
  * Ubuntu Linux - officially supported versions: 16.04 LTS, 18.04 LTS
  * CentOS - officially supported versions: ?
  * Mac OS X - officially supported versions: ?

### Definitions

* DefectDojo - the source code and supporting files for DefectDojo contained in the Github repo at https://github.com/DefectDojo/django-DefectDojo
* Dojo dependencies - any additional software, libraries or services needed to install and run the software in the DefectDojo repo.  This includes Django and other pip packages, celery workers, and any binaries required to run DefectDojo
* 3rd party services - additional services not maintained by DefectDojo but needed to run DefectDojo - currently a database

### Command-line options

```
 ./setup.bash --help
Usage: ./setup.bash [OPTION]...

Install DefectDojo in an interactive (default) or non-interactive method

Options:
  -h or --help             Display this help message and exit with a status code of 0
  -n or --non-interactive  Run install non-interactivity e.g. for Dockerfiles or automation

Note: No options are required, all are optional
```

### Installer details

setup.bash relies on the following files and directory structure:

```
setup.bash => the main install program
├── scripts
    ├── common
        ├── config-vars.sh
        ├── cmd-args.sh
        ├── prompt.sh
```

Install configuration is in [config-vars.sh](scripts/common/config-vars.sh) contains the following install options and default values:

**Format for this list:** *install option* [default value] - *definition*

* PROMPT [true] - Run the install in interactive mode aka prompt the user for config values
* DB_TYPE [MySQL] - The database type to be used by DefectDojo
* DB_LOCAL [true] - Boolean for if the database is installed locally aka on the same OS as DefectDojo
* DB_EXISTS [false] - Boolean for if the database already exists for DefectDojo to use aka doesn't need to be installed
* DB_NAME [dojodb] - Name of the database created to store DefectDojo data
* DB_USER [dojodbusr] - Database username used to access the DefectDojo database
* DB_PASS [vee0Thoanae1daePooz0ieka] - Default password used only for Dev installs, otherwise a random 24 character password is created at install time
* DB_HOST [localhost] - Database hostname where the DefectDojo database is located
* DB_PORT [3306] - Port database is listening on, default port is for the default database MySQL
* DB_DROP_EXISTING [true] - If the database name already exists in database server for DefectDojo, drop that database if this is true.  If false and a database name match occurs, throw an error and exit the installer.
* OS_USER=${OS_USER:-"dojo-srv"}
* OS_PASS=${OS_PASS:-"wahlieboojoKa8aitheibai3"}
* OS_GROUP=${OS_GROUP:-"dojo-srv"}
* INSTALL_ROOT=${INSTALL_ROOT:-"/opt/dojo"}
* DOJO_SOURCE=${DOJO_SOURCE:-"$INSTALL_ROOT/django-DefectDojo"}
* DOJO_FILES=${DOJO_FILES:-"$INSTALL_ROOT/local"}
* MEDIA_ROOT=${MEDIA_ROOT:-"$DOJO_FILES/media"}
* STATIC_ROOT=${STATIC_ROOT:-"$DOJO_FILES/static"}
* ADMIN_USER=${ADMIN_USER:-"admin"}
* ADMIN_PASS=${ADMIN_PASS:-"admin"}
* ADMIN_EMAIL=${ADMIN_EMAIL:-"ed@example.com"}

Configuration items for setup.py are in template-env in ./dojo/settings/ and contain


### Installers workflow

1. Check for command-line arguments, if none, do an interactive single server install
2. Check for install OS
3. Bootstrap any software needed by the install process
4. Install Dojo dependencies
5. Install 3rd party services


### Installer Bash variables

* SETUP_BASE : The full path to where the setup.bash file is located e.g ./setup if starting from the Dojo repository root
* REPO_BASE : The full path to where the DefectDojo source was cloned usually /opt/dojo/django-DefectDojo
* LIB_PATH : The full path to where the configuration values and libraries are for the DefectDojo installer which is SETUP_BASE + /scripts/common/
* DB_TYPPE : The database type DefectDojo will use - currently either SQLite, MySQL or PostgreSQL

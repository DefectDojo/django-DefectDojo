# Debian- or RHEL-based Bash Install Script (QUICK VERSION)

There is a script in the main folder called `setup.bash` that will allow you to
interactively install DefectDojo on many Linux-based systems. We do not
recommend running DefectDojo as root, but you may do so if you choose. This is
the quick version of the installation instructions, but if you want more details
about what's going on, check out
[Jay's wiki page](https://github.com/rackerlabs/django-DefectDojo/wiki/DefectDojo-Installation-Guide---Ubuntu-Desktop-14.04)
on Ubuntu 14.04 installation (most steps should be applicable to other distros
as well).


__You will need:__

- MySQL
- pip

__Recommended:__

- virtualenv

__Instructions:__

0. _(OPTIONAL)_ If you haven't already, run `mysql_secure_install` to set a
password for your root MySQL user
0. _(OPTIONAL)_ Set up a new virtualenv
0. Create a MySQL user with CREATE privileges, or use root __(not recommended)__
0. Run the `setup.bash` script, entering the required information to create a
MySQL database, install dependencies, and set up a Django superuser. If
installation is successful, you will see something like the following:

        ==============================================================================

        SUCCESS! Now edit your settings.py file in the 'dojo' directory to complete the installation.

        When you're ready to start the DefectDojo server, type in this directory:
            1. python manage.py bower install
            2. python manage.py collectstatic
            3. python manage.py runserver
    

0. Edit the settings.py file to modify any other settings that you want to 
change, such as your SMTP server information, which we leave off by default.
0. Install bower dependencies by running

        python manage.py bower install

0. Install static files to the correct directories

        python manage.py collectstatic

0. When you are ready to run DefectDojo, run the server with

        python manage.py runserver

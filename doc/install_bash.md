# Debian- or RHEL-based Linux Install (Bash Script)

There is a script in the main folder called `setup.bash` that will allow you to
interactively install TestTrack on some Linux-based systems. The user
you use to run the installation script will need sudo access, but should not
be the root account.

__You will need:__

- MySQL
- pip

__Recommended:__

- virtualenv

__Instructions:__

0. _(OPTIONAL)_ Set up a new virtualenv
0. Create a MySQL user with CREATE privileges
0. Run the `setup.bash` script, entering the required information to create a
MySQL database, install dependencies, and set up a Django superuser.
0. Edit the settings.py file to modify any other settings that you want to 
change, such as your SMTP server information, which we leave off by default.
0. When you are ready to run TestTrack, run the server with

    `python manage.py runserver`

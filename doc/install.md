# Installation

## Vagrant

Installing with Vagrant is the easiest way to get started with TestTrack.

__You will need:__

- Vagrant
- VirtualBox
- Ansible

__Instructions:__

0. Modify the variables in `ansible/vars.yml` to fit your desired configuration
0. Type `vagrant up` in the repo's root directory
0. If you have any problems during setup, run `vagrant provision` once you've
fixed them to continue provisioning the server 
0. If you need to restart the server, you can simply run `vagrant provision`
again


## Debian- or RHEL-based Install Script

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

    python manage.py runserver

# Description

![Screenshot of TestTrack](./doc/img/screenshot1.png)

TestTrack is a tool created by the Security Engineering team at Rackspace to
track testing efforts. It attempts to streamline the testing process by
offering features such as templating, report generation, metrics, and baseline
self-service tools. Though it was designed with security folks in mind, there
is nothing keeping QA/QE testers, or any other testers for that matter, from
using it productively.

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

For more information, please see
[the doc folder](./doc)

# About Us

TestTrack is maintained by:

- Greg Anderson ([@\_GRRegg](https://twitter.com/_GRRegg))
- Charles Neill ([@ccneill](https://twitter.com/ccneill))
- Jay Paz ([@jjpaz](https://twitter.com/jjpaz))

With past contributions from:

- Fatimah Zohra
- Michael Dong

# License

<a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by-sa/4.0/88x31.png" /></a><br /><span xmlns:dct="http://purl.org/dc/terms/" property="dct:title">TestTrack</span> created by <span xmlns:cc="http://creativecommons.org/ns#" property="cc:attributionName">Greg Anderson, Charles Neill, and Jay Paz</span> is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/">Creative Commons Attribution-ShareAlike 4.0 International License</a>.

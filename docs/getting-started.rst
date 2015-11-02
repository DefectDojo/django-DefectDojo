Getting Started
===============

Demo
----

If you'd like to check out a demo of DefectDojo before installing it, you can check out our `PythonAnywhere demo site`_.

.. _PythonAnywhere demo site: https://defectdojo.pythonanywhere.com

You can log in as an administrator like so:

.. image:: /_static/admin-creds.png

You can also log in as a product owner / non-staff user:

.. image:: /_static/prod-owner-creds.png

Installation
------------

.. _debian-or-rhel-based-bash-install-script:

Debian or RHEL based Bash Install Script
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There is a script in the main folder called `setup.bash` that will allow you to
interactively install DefectDojo on many Linux-based systems. We do not
recommend running DefectDojo as root, but you may do so if you choose. This is
the quick version of the installation instructions, but if you want more details
about what's going on, check out `this wiki page`_ on Ubuntu 14.04 installation
(most steps should be applicable to other distributions as well).

.. _this wiki page: https://github.com/rackerlabs/django-DefectDojo/wiki/DefectDojo-Installation-Guide---Ubuntu-Desktop-14.04

**You will need:**

* MySQL
* pip

**Recommended:**

* virtualenv

**Instructions:**

#. *(OPTIONAL)* If you haven't already, run `mysql_secure_install` to set a
   password for your root MySQL user
#. *(OPTIONAL)* Set up a new virtualenv
#. Create a MySQL user with CREATE privileges, or use root *(not recommended)*
#. Run the `setup.bash` script, entering the required information to create a
   MySQL database, install dependencies, and set up a Django superuser. If
   installation is successful, you will see something like the following: ::

        ==============================================================================

        SUCCESS! Now edit your settings.py file in the 'dojo' directory to complete the installation.

        When you're ready to start the DefectDojo server, type in this directory:
            1. python manage.py bower install
            2. python manage.py collectstatic
            3. python manage.py runserver


#. Edit the settings.py file to modify any other settings that you want to
   change, such as your SMTP server information, which we leave off by default.
#. Install bower dependencies by running
        ``python manage.py bower install``
#. Install static files to the correct directories
        ``python manage.py collectstatic``
#. When you are ready to run DefectDojo, run the server with
        ``python manage.py runserver``

Vagrant Install
~~~~~~~~~~~~~~~

.. note::
    We recommend only installing with Vagrant for development / testing purposes. If you are deploying to
    production, we recommend following the quick :ref:`debian-or-rhel-based-bash-install-script`, or if you're on Ubuntu
    14.04, check out `this wiki page`_, on Ubuntu installation, complete with in-depth instructions and explanations.

*You will need:*

* Vagrant
* VirtualBox
* Ansible

*Instructions:*

#. Modify the variables in `ansible/vars.yml` to fit your desired configuration
#. Type ``vagrant up`` in the repo's root directory
#. If you have any problems during setup, run ``vagrant provision`` once you've fixed them to continue provisioning the
   server
#. If you need to restart the server, you can simply run ``vagrant provision`` again

By default, the server will run on port 9999, but you can configure this in the ``vars.yaml`` file.


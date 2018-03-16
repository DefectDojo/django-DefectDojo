Getting Started
===============

*Demo*
If you'd like to check out a demo of DefectDojo before installing it, you can check out on our `PythonAnywhere demo site`_.

.. _PythonAnywhere demo site: https://defectdojo.pythonanywhere.com

You can log in as an administrator like so:

.. image:: /_static/admin-creds.png

You can also log in as a product owner or non-staff user:

.. image:: /_static/prod-owner-creds.png

*Installation*


Change into the newly created ```django-DefectDojo``` directory:

    ``cd django-DefectDojo/``

There is a script in the main folder called ``setup.bash`` that will allow you to interactively install DefectDojo on any Linux based systems. We do not recommend running DefectDojo as root, but you may do so if you choose.

**You will need:**
* MySQL
* pip

**Recommended**
* virtualenv

1. If you haven't already, run ``mysql_secure_install`` to set a password for your root MySQL user.

2. Create a MySQL user with CREATE privileges, or use root.

**Run the ``setup.bash`` script**
This script will:

1. Install all the operating system packages needed

2. Prompt for database connection information and create the necessary table

3. Install all python packages needed

4. Run all DB migrations using Django's ``migrate`` command.

5. Provide you with the commands needed to complete the installation

Install Script
~~~~~~~~~~~~~~~

Run the script:

    ``./setup.bash``

During the execution you will be prompted for a few items:

    ``MySQL user (should already exist):``

Enter the user you created or `root` if you used ```mysql_secure_installation```

   ``Password for user:``

Enter the password for the MySQL user you selected.

    ``Database name (should NOT exist):``

Select a name for the DefectDojo database.

**All the packages**
It may take some time for all the `OS` and `python` packages to be installed. As of this writing the packages for this `OS` are:

* gcc
* libssl-dev
* python-dev
* libmysqlclient-dev
* python-pip
* mysql-server
* nodejs-legacy
* npm

And the `python` packages are (listed in `setup.py` as well):

* 'Django',
* 'MySQL-python',
* 'Pillow',
* 'django-tastypie',
* 'django-tastypie-swagger',
* 'gunicorn',
* 'python-nmap',
* 'pytz',
* 'requests',
* 'wsgiref',
* 'django-filter',
* 'supervisor',
* 'humanize'

After all the components have been installed, the `makemigrations` process will prompt you to create a ``superuser``

    ``You have installed Django's auth system, and don't have any superusers defined.
      Would you like to create one now? (yes/no):``

Answer `yes` and follow the prompts, this will be the user you will use to login to DefectDojo.
#. *(OPTIONAL)* If you haven't already, run `mysql_secure_install` to set a password for your root MySQL user.
#. Edit the settings.py file to modify any other settings that you want to
   change, such as your SMTP server information, which we leave off by default.
#. When you are ready to run DefectDojo, run the server with
        ``./run_dojo.bash``

Vagrant Install
~~~~~~~~~~~~~~~


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

Docker Install
~~~~~~~~~~~~~~~

There are three versions of Docker Dojo. The first version is a development / testing version, the second is a docker
compose file with Nginx, MySQL and DefectDojo and the third is a Docker Cloud file for Docker Cloud.

Docker Local Install
*************

*You will need:*

* Latest version of Docker

*Instructions:*

#. Run the docker command to pull the latest version of DefectDojo.
        ``docker run -it -p 8000:8000 appsecpipeline/django-defectdojo bash -c "export LOAD_SAMPLE_DATA=True && bash /django-DefectDojo/docker/docker-startup.bash"``
#. Navigate to: http://localhost:8000 and login with the credentials shown in the terminal.

Docker Compose Install
*************

*You will need:*

* Latest version of Docker
* Latest version Docker Compose

*Instructions:*

#. Clone the `Docker Cloud DefectDojo`_ Repo
        ``git clone https://github.com/aaronweaver/docker-DefectDojo``
#. Change directories into the newly created folder.
        ``cd docker-DefectDojo``
#. Run the setup.bash script which will create a random password for MySQL and Dojo and other setup tasks.
        ``bash setup.bash``
#. Run Docker Compose.
        To run docker-DefectDojo and see the Dojo logs in the terminal, use:
        ``docker-compose up``

        To run docker-DefectDojo and get your terminal prompt back, use:
        ``docker-compose up -d``
#. Navigate to https://localhost and login with the username and password specified in the setup.bash script.

.. _Docker Cloud DefectDojo: https://github.com/aaronweaver/docker-DefectDojo

Docker Cloud Install
*************

*Instructions:*

* Log into `DockerCloud`_.
* Click on Stacks and then Create Stack.
* Name the Stack, DefectDojo for example.
* Copy the Docker Compose file from the `Docker DefectDojo Repo`_.
* Edit the ``DOJO_ADMIN_PASSWORD``, ``MYSQL_PASSWORD`` and ``MYSQL_ROOT_PASSWORD``. Each of these is labeled as: ChangeMe. Note: Make sure the passwords both match for ``dojo:MYSQL_PASSWORD`` and ``mysql:MYSQL_PASSWORD``.
* Click 'Create and Deploy'
* Once the services are running then login with the username and password specified in the YAML file.

.. _DockerCloud: https://cloud.docker.com
.. _Docker DefectDojo Repo: https://raw.githubusercontent.com/aaronweaver/docker-DefectDojo/master/docker-cloud.yml

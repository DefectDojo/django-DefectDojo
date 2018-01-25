Ansible playbook for Defect Dojo
===================================
This Ansible Playbook is designed to setup Development and Production Defect Dojo environments on Linux. It can install and configure following applications that are commonly used in production Django deployments:

- Nginx (Web Server)
- Gunicorn (App Server)
- PostgreSQL ( Database )
- MySQL ( Database )
- Supervisor ( Process Control )
- Virtualenv (Isolation for python environments)
- Letsencrypt (CA)

## TL;DR - Quick Setup

A quick way to get started is with Vagrant.

### Requirements

Install the following software

- [Ansible >= 2.2 ](http://docs.ansible.com/intro_installation.html)
- [Vagrant > 2.0 ](http://www.vagrantup.com/downloads.html)
- [VirtualBox](https://www.virtualbox.org/wiki/Downloads) or [Docker](https://www.docker.com/get-docker)

### Dev Setup

1. Open up terminal or command prompt and type the following commands.

	```bash
	git clone https://github.com/OWASP/django-DefectDojo.git
	cd django-DefectDojo/ansible
	vagrant up

	sudo echo "192.168.33.18 defect.dojo" > /etc/hosts # you might have to edit this line manually on windows
	```

	Wait a few minutes for the magic to happen. Yup, exactly, you just provisioned a completely new server and deployed an entire Django stack with SSL in 5 minutes with _two words(vagrant up)_ :).

2. visit ``` https://defect.dojo``` to login using credentials.

### Production Setup

1. Open up terminal or command prompt and type the following commands.

	```bash
	git clone https://github.com/OWASP/django-DefectDojo.git
	cd django-DefectDojo/ansible
	```
2. Edit `production.yml` and `production` inventory file to suit your needs (change passwords, private key path, database type etc.,). Use `grep 'var_name' -r .` to find out where a particular variable is set.

3. Run the following command

	```bash
	ansible-playbook -i production production.yml
	```

2. visit ``` https://prod-hostname``` to login using the credentials set in production.yml.

## Configurations Details

All settings(db, nginx, ssl etc.,) are stored in ```vars/all.yml``` for ease however to enable deployment across dev and production environments you should override `vars/development.yml or vars/production.yml` instead of using `vars/all.yml`. If you wish to change some defaults specific to a role, they are available under `roles/role_name/defaults/main.yml`.

Since we are running a security tool, we should have TLS(https), so `certbot` role is also included for automatically generating and renewing trusted SSL certificates with [Let's Encrypt](https://letsencrypt.org/).

**Tested with OS:** Ubuntu 16.04 LTS (64-bit PC), Ubuntu 14.04 LTS (64-bit PC)

**Tested with Cloud Providers:** [Amazon](https://aws.amazon.com), [Rackspace](http://www.rackspace.com/)

### Configuring your application

The main settings to change are in the [vars/base.yml](vars/base.yml) file, where you can configure the location of your Git project, the project name, and the application name which will be used throughout the Ansible configuration.

Some of the defauls are:

__Project name__: defect-dojo

__Installation directory__: /opt/dojo

__Repo code directory__: /opt/dojo/defect-dojo

__Gunicorn start script (environment variables)__: /opt/dojo/bin/gunicorn_start

If you wish to override some defaults, you can change them in all.yml or `vars/development.yml or vars/production.yml` based on what you are using.

The django app installation happens under the role `web `at ```roles/web/tasks/setup_django_app.yml```

Also, if your app needs additional system packages installed, you can add them in `roles/web/tasks/install_additional_packages.yml`.

### Vagrant commands for managing Development Environment

**SSH to the box**

```
vagrant ssh
```

**Re-provision the box to apply the changes you made to the Ansible configuration**

```
vagrant provision
```

**Reboot the box**

```
vagrant reload
```

**Shutdown the box**

```
vagrant halt
```

## Running the Ansible Playbook to provision servers

Create an inventory file for the environment, for example:

```
# development

[webservers]
webserver1.example.com
webserver2.example.com

[dbservers]
dbserver1.example.com
```

Next, create a playbook for the server type. See [webservers.yml](webservers.yml) for an example.

Run the playbook:

```
ansible-playbook -i development webservers.yml
```

You can also provision an entire site by combining multiple playbooks.  For example, I created a playbook called `site.yml` that includes both the `webservers.yml` and `dbservers.yml` playbook.

A few notes here:

- The `dbservers.yml` playbook will only provision servers in the `[dbservers]` section of the inventory file.
- The `webservers.yml` playbook will only provision servers in the `[webservers]` section of the inventory file.

You can then provision the entire site with this command:

```
ansible-playbook -i development site.yml
```

If you're testing with vagrant, you can use this command from directory where `Vagrantfile` is present:

```
ansible-playbook -i vagrant_ansible_inventory --private-key=./.vagrant/machines/defect.dojo/virtualbox/private_key -vv site.yml

```

If you're deploying to amazon EC2 or Digital Ocean's Droplet make sure your inventory knows where your private key by using inventory file as shown below.

```
# Production

[webservers]
webserver1.example.com ansible_ssh_host=webserver1.example.com ansible_ssh_port=22 ansible_ssh_user='ubuntu' ansible_ssh_private_key_file='~/amazon-ec2.pem'

[dbservers]
dbserver1.example.com
```

## Using Ansible for Django Deployments

When doing deployments, you can simply use the `--tags` option to only run those tasks with these tags.

For example, you can add the tag `deploy` to certain tasks that you want to execute as part of your deployment process and then run this command:

```
ansible-playbook -i stage webservers.yml --tags="deploy"
```

This repo already has `deploy` tags specified for tasks that are likely needed to run during deployment in most Django environments.

## Advanced Options

### Changing the Ubuntu release

The [Vagrantfile](Vagrantfile) uses the Ubuntu 16.04 LTS Vagrant box for a 64-bit PC that is published by Canonical in HashiCorp Atlas. To use Ubuntu 14.04 LTS instead, change the `config.vm.box` setting to `ubuntu/trusty64`. To use the Vagrant box for a 32-bit PC, change this setting to `ubuntu/xenial32` or `ubuntu/trusty32`.

### Automatically generating and renewing Let's Encrypt SSL certificates with the certbot client

A `certbot` role has been added to automatically install the `certbot` client and generate a Let's Encrypt SSL certificate.

**Requirements:**

- A DNS "A" or "CNAME" record must exist for the host to issue the certificate to.
- The `--standalone` option is being used, so port 80 or 443 must not be in use (the playbook will automatically check if Nginx is installed and will stop and start the service automatically).

In `roles/nginx/defaults/main.yml`, you're going to want to override the `nginx_use_letsencrypt` variable and set it to yes/true to reference the Let's Encrypt certificate and key in the Nginx template.

In `roles/certbot/defaults/main.yml`, you may want to override the `certbot_admin_email` variable.

A cron job to automatically renew the certificate will run daily.  Note that if a certificate is due for renewal (expiring in less than 30 days), Nginx will be stopped before the certificate can be renewed and then started again once renewal is finished.  Otherwise, nothing will happen so it's safe to leave it running daily.

## TODO
- [ ] Support Redhat/CentOS
- [ ] Add Celery Support

## Useful Links

- [Ansible - Best Practices](http://docs.ansible.com/playbooks_best_practices.html)
- [Setting up Django with Nginx, Gunicorn, virtualenv, supervisor and PostgreSQL](http://michal.karzynski.pl/blog/2013/06/09/django-nginx-gunicorn-virtualenv-supervisor/)
- [How to deploy encrypted copies of your SSL keys and other files with Ansible and OpenSSL](http://www.calazan.com/how-to-deploy-encrypted-copies-of-your-ssl-keys-and-other-files-with-ansible-and-openssl/)

## Credits
This playbook heavily relies on [Jonathan's playbook](https://github.com/jcalazan/ansible-django-stack)

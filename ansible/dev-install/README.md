## Using the Developer install of Defect Dojo

**Requirements:**

* Ansible installed - at least version 2.2.x
* A Ubuntu 16.04 64-bit Linux install with
* * SSH running
* * A user with sudo privileges

### Installing Defect Dojo

(1) Create a inventory file based on EXAMPLE-inventory

You'll add the IP address of the deploy target, the user & passwords to run sudo

```
$ cp ./EXAMPLE-inventory ./inventory
$ vi inventory
```

(2) Edit deploy-vars.yml

You'll need the IP address of the deploy target and its hostname at the least.  The rest of the variables defined in that file are sane defaults but you're welcome to change them to fit your needs.

```
$ vi deploy-vars.yml
```

(3) Run the dojo-dev-environment.yml playbook - that its!

```
$ ansible-playbook dojo-dev-environment.yml
```

Go grab your favorite beverage and enjoy watching the install scroll by.


Here's an example run done against a VM running in VirturalBox:

```
$ ansible-playbook dojo-dev-environment.yml

PLAY [all] *********************************************************************

TASK [raw] *********************************************************************
changed: [192.168.56.101]

TASK [setup] *******************************************************************
ok: [192.168.56.101]

TASK [Set hostname] ************************************************************
ok: [192.168.56.101]

TASK [Set IP and hostname in /etc/hosts] ***************************************
ok: [192.168.56.101]

TASK [Get latest pages aka "apt-get update"] ***********************************
ok: [192.168.56.101]

TASK [Install Dojo Prerequisites] **********************************************
ok: [192.168.56.101] => (item=[u'python-simplejson', u'git', u'mysql-server', u'nodejs', u'npm', u'python-pip', u'libjpeg-dev', u'libxrender1', u'libfontconfig1', u'python-mysqldb', u'libmysqlclient-dev', u'expect'])

TASK [Check for existing wkhtmltox install] ************************************
ok: [192.168.56.101]

TASK [Install wkhtmltox for report generation] *********************************
skipping: [192.168.56.101]

TASK [Download and extract wkhtmltox tarball] **********************************
skipping: [192.168.56.101]

TASK [Move wkhtmltopdf into /usr/bin] ******************************************
skipping: [192.168.56.101]

TASK [Check for existing Defect Dojo install] **********************************
ok: [192.168.56.101]

TASK [Create database for new Defect Dojo install] *****************************
ok: [192.168.56.101]

TASK [Set DB user and password for Defect Dojo] ********************************
ok: [192.168.56.101]

TASK [Adjust adduser.conf to allow for periods in usernames] *******************
ok: [192.168.56.101]

TASK [Add the dojo group] ******************************************************
ok: [192.168.56.101]

TASK [Add the dojo user] *******************************************************
ok: [192.168.56.101]

TASK [Create Defect Dojo base directory] ***************************************
ok: [192.168.56.101] => (item=/opt/defect-dojo)
ok: [192.168.56.101] => (item=/opt/defect-dojo/dojo)

TASK [Install a very basic requirements.txt] ***********************************
ok: [192.168.56.101]

TASK [Install virtualenv] ******************************************************
ok: [192.168.56.101]

TASK [Setup Virtual Environment] ***********************************************
ok: [192.168.56.101]

TASK [Checkout latest Defect Dojo source from GitHub] **************************
ok: [192.168.56.101]

TASK [Update Defect Dojo to latest source from GitHub] *************************
skipping: [192.168.56.101]

TASK [Install yarn] ***********************************************************
ok: [192.168.56.101]

TASK [Make sure node is in the path] *******************************************
ok: [192.168.56.101]

TASK [Create a settings.py for Defect Dojo] ************************************
changed: [192.168.56.101]

TASK [Generate a secret key for Defect Dojo] ***********************************
changed: [192.168.56.101]

TASK [Add new secret key into settings.py] *************************************
changed: [192.168.56.101]

TASK [Pip install the required modules in the Defect Dojo virtual env] *********
changed: [192.168.56.101]

TASK [Django migrate] **********************************************************
ok: [192.168.56.101]

TASK [Django syncdb] ***********************************************************
ok: [192.168.56.101]

TASK [Django loaddata product_type] ********************************************
ok: [192.168.56.101]

TASK [Django loaddata test_type] ***********************************************
ok: [192.168.56.101]

TASK [Django loaddata development_environment] *********************************
ok: [192.168.56.101]

TASK [Django installwatson] ****************************************************
ok: [192.168.56.101]

TASK [Django buildwatson] ******************************************************
ok: [192.168.56.101]

TASK [Change ownership of Defect Dojo to dojo user] ****************************
changed: [192.168.56.101]

TASK [Install yarn components] ************************************************
changed: [192.168.56.101]

TASK [Django collectstatic] ****************************************************
ok: [192.168.56.101]

TASK [Create a script to check for Django admin user] **************************
ok: [192.168.56.101]

TASK [Run script to check for Django admin] ************************************
changed: [192.168.56.101]

TASK [Create Django super user] ************************************************
skipping: [192.168.56.101]

TASK [Add script to change Django super user password] *************************
changed: [192.168.56.101]

TASK [Change password] *********************************************************
changed: [192.168.56.101]

TASK [Clean-up password change script] *****************************************
changed: [192.168.56.101]

TASK [Setup logging directory] *************************************************
ok: [192.168.56.101]

TASK [Add Defect Dojo startup script] ******************************************
ok: [192.168.56.101]

TASK [Startup Defect Dojo] *****************************************************
ok: [192.168.56.101]

TASK [Defect Dojo install completed] *******************************************
ok: [192.168.56.101] => {
    "msg": "Defect Dojo is listening on port 8000 - http://10.1.1.101:8000 or http://defect-dojo.pvt:8000 if DNS is setup"
}

PLAY RECAP *********************************************************************
192.168.56.101             : ok=45   changed=11   unreachable=0    failed=0   

$
```

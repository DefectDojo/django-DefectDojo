# DefectDojo HowTo: Run the django-DefectDojo in a Single Docker Container

## Why do you need to run this stuff
Run the django-DefectDojo in a single Docker container may be useful if you:
* have not so big environment
* want to train with the product but persist your data
* want to develop and create your small dev environment :)

## Clone repository of django-DefectDojo and switch to dev branch
```
git clone https://github.com/DefectDojo/django-DefectDojo.git
cd django-DefectDojo
git checkout dev
```

## Navigate to setup/single-container directory
```
cd setup
cd single-container
```

## Create directories for application and database and run defectdojo_init.sh script

```
mkdir ddjdb
mkdir ddjapp
sudo ./defectdojo_init.sh -imagename=ddj_dev -appdir=${PWD}/ddjapp -dbdir=${PWD}/ddjdb -port=8001
```

## Create your working image and make test run

```
sudo ./defectdojo_install.sh -imagename=ddj_dev -appdir=${PWD}/ddjapp -dbdir=${PWD}/ddjdb -port=8001
```

## Run your application in working mode

```
sudo docker start ddj_dev
```

## Reset admin password for web interface.

This item created with great appreciate to @Sudneo comment in https://github.com/DefectDojo/django-DefectDojo/issues/642

Enter into the container shell

```
sudo docker exec -it defectdojoapp bash
```

Run mysql client for local server

```
mysql
```

Execute commands in the mysql shell

```
use dojodb;
UPDATE auth_user SET password='pbkdf2_sha256$36000$sT96yObJtsFk$F9YAJimsQqBXnff/QGLNTv100qhCNl/23hoBuNtSNZU=' WHERE username='admin';
quit;
```

## Log in to your django-DefectDojo instance

Navigate to http://127.0.0.1:8000/ in your browser and login with admin:admin pair.

## Future errors possible

### Can't connect to defectDojo web server, errors in MySql logs
```
django.db.utils.OperationalError: (2002, "Can't connect to local MySQL server through socket '/var/run/mysqld/mysqld.sock' (2)")
```

Check for mysql errors from the inside of the container:

```
$ sudo docker exec -it defectdojoapp bash
# cat /var/log/mysql/error.log
```

If you will see such string:

```
...
2020-02-21T12:45:50.627311Z 11 [Note] Access denied for user 'debian-sys-maint'@'localhost' (using password: YES)
...
```

Then do this:

* run shell inside your defectDojo container
```
$ sudo docker exec -it <YOUR_DDJ_CONTAINER> bash
# cat /etc/mysql/debian.cnf
[client]
host     = localhost
user     = debian-sys-maint
password = 8cCEV9J6GHdiQ7ea
socket   = /var/run/mysqld/mysqld.sock
[mysql_upgrade]
host     = localhost
user     = debian-sys-maint
password = 8cCEV9J6GHdiQ7ea
socket   = /var/run/mysqld/mysqld.sock
```
Copy the password from this file into the clipboard and execute following commands (in the same bash):
```
# mysql
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 4
Server version: 5.7.29-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2020, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> GRANT ALL PRIVILEGES ON *.* TO 'debian-sys-maint'@'localhost' IDENTIFIED BY '<COPIED_PASSWORD>';
Query OK, 0 rows affected, 1 warning (0.00 sec)

mysql> quit

# exit
```

Restart your container and be happy:
```
$ sudo docker restart <YOUR_DDJ_CONTAINER>
```
Thanks to [this thread from StackOverflow](https://stackoverflow.com/questions/11644300/access-denied-for-user-debian-sys-maint) will be helpful.

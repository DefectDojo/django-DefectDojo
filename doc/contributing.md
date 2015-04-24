# Contributing to DefectDojo

There are a few things to keep in mind when developing your own code for
DefectDojo

## Modifying Application Settings

0. You must keep
[ansible/roles/webserver/templates/settings.j2][settings_template]
up to date with [dojo/settings.dist.py][dojo_settings] as you make
changes to your settings if you want to install via the Vagrant provisioning
script, or if you want to submit a pull request to DefectDojo. You should define
any additional variables needed upon install in
[ansible/vars.yml][ansible_vars]

0. If you want to make changes to the DefectDojo code and test it with Vagrant,
you will need to change the `dd_git_repo` and/or `dd_git_branch` variables
defined in [ansible/vars.yml][ansible_vars]


[settings_template]: ../ansible/roles/webserver/templates/settings.j2 "Ansible settings template"
[dojo_settings]: ../dojo/settings.dist.py "DefectDojo settings file"
[ansible_vars]: ../ansible/vars.yml "Ansible variables file"

# Contributing to DefectDojo

Here are a few things to keep in mind when making changes to DefectDojo.

## Modifying DefectDojo and testing with Vagrant

This may change in the future, but for now the bash setup and Vagrant setup are
fairly decoupled.

If you want to make changes to the DefectDojo code and test it with Vagrant,
you will need to change the `dd_git_repo` and/or `dd_git_branch` variables
defined in [__ansible/vars.yml__][ansible_vars]. You will also need to port any
changes you make to [__dojo/settings.dist.py__][dojo_settings] into 
[__ansible/roles/webserver/templates/settings.j2__][ansible_settings], adding
Ansible variables as necessary (defined in
[__ansible/vars.yml__][ansible_vars]). Any additional pip packages will need to
be defined in [__ansible/roles/webserver/tasks/app.yml__][ansible_app].

## Submitting pull requests

The following are things to consider before submitting a pull request to
DefectDojo.

0. Ensure all changes made to the code, packages, etc. are reflected in the
[__setup.bash__][setup_bash] script, the [__setup.py__][setup_py] script, and
the Ansible playbooks in the [__ansible/__][ansible_folder] folder. See
[__Modifying DefectDojo and testing with Vagrant__][modifying_dojo] above for
more information.

0. If possible, make sure that both the bash and Vagrant installation scripts
are working properly before submitting a pull request.

0. All submitted code should conform to [__PEP8 standards__][pep8].


[ansible_vars]: /ansible/vars.yml "Ansible variables file"
[dojo_settings]: /dojo/settings.dist.py "DefectDojo settings file"
[ansible_settings]: /ansible/roles/webserver/templates/settings.j2 "Ansible settings template"
[setup_py]: /setup.py "Python setup script"
[ansible_app]: /ansible/roles/webserver/tasks/app.yml "Ansible app tasks"
[setup_bash]: /setup.bash "Bash setup script"
[ansible_folder]: /ansible "Ansible folder"
[modifying_dojo]: #modifying-defectdojo-and-testing-with-vagrant "Modifying DefectDojo and testing with Vagrant"
[pep8]: https://www.python.org/dev/peps/pep-0008/ "PEP8"

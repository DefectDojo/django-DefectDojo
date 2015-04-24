# Vagrant Install

__NOTE:__
We recommend only installing with Vagrant for development / testing purposes.
If you are deploying to production, we recommend following the quick 
[bash install guide](./install_bash.md), or if you're on Ubuntu 14.04, check out
[Jay's wiki page](https://github.com/rackerlabs/django-DefectDojo/wiki/DefectDojo-Installation-Guide---Ubuntu-Desktop-14.04),
on Ubuntu installation, complete with in-depth instructions and explanations.


__You will need:__

- Vagrant
- VirtualBox
- Ansible

__Instructions:__

0. Modify the variables in [ansible/vars.yml](../ansible/vars.yml) to fit your
desired configuration
0. Type `vagrant up` in the repo's root directory
0. If you have any problems during setup, run `vagrant provision` once you've
fixed them to continue provisioning the server 
0. If you need to restart the server, you can simply run `vagrant provision`
again

By default, the server will run on port 9999, but you can configure this in the
vars.yaml file.

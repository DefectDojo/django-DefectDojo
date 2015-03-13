# Vagrant Install

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

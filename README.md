# NETSCOUT<sup>®</sup> AED Ansible Modules

This repository contains a collection of Ansible modules that allow you to configure and manage NETSCOUT Arbor Edge Defense (AED) appliances with Ansible.


## Prerequisites

To use the modules in this repository, you need:

- [Ansible](https://ansible.com)
- One or more AED appliances with AED software, version 6.2 or greater
- One of the following types of login credentials for each AED appliance:
  - username and password
  - an API token

## Installation instructions

Clone this repository to the machine on which Ansible is installed.

Use the `aed` role from this repository as is
or copy it into your existing playbook directory structure.

The `/roles/aed/` directory is an Ansible [role](https://docs.ansible.com/ansible/latest/user_guide/playbooks_reuse_roles.html) for AED appliances.
Per the standard for Ansible roles, it contains the following subdirectories:

* `aed/defaults/`: The default values for variables that you must set to use the aed role.
* `aed/httpapi_plugins/`: The httpapi connection plugins that you need to connect to the AED appliances.
* `aed/library/`: The Ansible modules for performing tasks on the AED appliances.
* `aed/module_utils/`: The common Python modules that the Ansible modules use.
* `aed/tasks/`: The tasks to perform on the AED appliances.

Due to a possible bug in Ansible,
you must set the [`httpapi_plugins`](https://docs.ansible.com/ansible/latest/reference_appendices/config.html#default-httpapi-plugin-path) option in your Ansible config
file to the `httpapi_plugins/` subdirectory in the `aed` role. For an example of how to set this option,
see the `ansible.cfg` file in this repository.

*IMPORTANT: If you do not perform this operation before you use the aed role, Ansible will not load the AED httpapi plugin correctly
and a "`socket_path does not exist or cannot be found`" error may occur.*

Add the AED appliances to your inventory.
The `hosts.example` file in this repository contains some examples of how to set the login credentials:

* For password-based authentication, set the `ansible_user` and `ansible_password` variables.
* For API token-based authentication, set the `ansible_httpapi_aed_api_token` variable.

To customize the `aed` role, create an `aed/tasks/main.yaml` file,
and add the tasks to perform on the AED.
The ``example_tasks/`` directory contains some examples of AED tasks.

*IMPORTANT: Do not copy the tasks verbatim as they are  meant to be example use cases only.*

If necessary, create a new `aed/vars/main.yaml` file to modify the default variables set in `aed/defaults/main.yaml`.
In most cases, this should not be necessary.

You can now add the `aed` role to your main playbook.
The `playbook.yaml` file that is included in this repository provides a simple example of how to use this role.

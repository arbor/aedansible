#!/usr/bin/python

# Copyright: (c) 2019, NETSCOUT
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: aed_pg
version_added: "2.7"
author: "Chris Hartmann, <ansible-aed@netscout.com>"
short_description: Manage the AED protection groups
description:
  - Use this module to add, delete, and configure the protection groups on an AED device.
notes:
  - This module supports check mode.
options:
  pg_name:
    description:
      - Specifies the name of the protection group.
        If the protection group does not exist, this option adds the protection group.
        If the protection group exists, this option modifies the specified configuration settings, if any.
    required: true
    type: str

  pg_active:
    description:
      - Toggles the protection mode for the protection group.
    required: false
    type: bool

  pg_protected_hosts:
    description:
      - Specifies a comma-separated list of IP addresses or host names that the protection group protects.
        Required if you are adding a new protection group.
    required: false
    type: str

  pg_server_type:
    description:
      - Specifies the name of the server type that the protection group uses.
        Required if you are adding a new protection group.
    required: false
    type: str

  pg_description:
    description:
      - Provides a user-defined description for the protection group.
    required: false
    type: str

  pg_protection_level:
    description:
      - Sets the protection level for the protection group.
    choices: ['global', 'low', 'medium', 'high']
    required: false
    type: str

  pg_present:
    description:
      - Determines if the protection group exists, and, if this option is set to false, removes the protection group.
    required: false
    type: bool
"""

EXAMPLES = """
---
- name: Set the protection group
  aed_pg:
    pg_name: test1
    pg_active: yes
    pg_protected_hosts: 1.1.1.1/32,10.10.10.0/24,8.6.7.5/32
    pg_server_type: DNS Server
    pg_description: Description of test1 protection group
    pg_protection_level: global
    pg_present: yes

"""

RETURN = """
aed_pg_state:
  description: Returns the protection group's configuration.
  returned: When the protection group is present
  type: dict
  sample: {
      "pg_active": true,
      "pg_description": "Description of test2 protection group",
      "pg_name": "test2",
      "pg_protected_hosts": ["2.2.2.2/32", "20.20.20.0/24"],
      "pg_protection_level": "global",
      "pg_server_type": "DNS Server"
    }

changed:
  description: Returns a value that indicates if any changes were made to the protection group.
  type: bool
  returned: Always

create_pg:
    description: Returns the name of the protection group, if the protection group is new.
    type: str
    returned:  When you add a new protection group

delete_pg:
    description: Returns the name of the deleted protection group.
    type: str
    returned:  When you delete a protection group

no_create:
    description: If you set the pg_present option to false for a pg_name that does not exist,
                 returns the name of the protection group that was not created or deleted.
    type: str
    returned: When you try to delete a non-existent protection group
"""

import json
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ansible.module_utils.network.aed.aed import (AEDAPIBase,
                                                  AEDAPIError,
                                                  ans_to_rest,
                                                  rest_to_ans,
                                                  get_changes,
                                                  get_want,
                                                  ResponseCodes,
                                                  exception_context)


def morph_pg_active(var):
    """Convert active/inactive state between integer and bool"""
    if isinstance(var, int):
        return True if var == 1 else False
    return 1 if var is True else 0


def morph_pg_protection_level(var):
    """Convert a protection level to string if integer, or vice-versa"""
    if var is None:
        return 'global'

    if isinstance(var, int):
        return ['low', 'medium', 'high'][var - 1]

    if var == 'global':
        return None

    return ['low', 'medium', 'high'].index(var) + 1


PARAM_MAP = [
    ('pg_name', 'name', str),
    ('pg_active', 'active', morph_pg_active),
    ('pg_protected_hosts', 'prefixes', list),
    ('pg_server_type', 'serverType', None),
    ('pg_description', 'description', str),
    ('pg_protection_level', 'protectionLevel', morph_pg_protection_level),
    ('pgid', 'pgid', int)
]


def check_args(module, server_types):
    """Check that serverType is legit

    Args:
        module: AnsibleModule instance
        server_types (dict): dict of serverType(str): id(int)

    Returns:
        Returns an error if the passed server type
        does not exist.
    """
    _st = module.params.get('pg_server_type')
    if _st and _st not in server_types:
        raise AEDAPIError('\'{}\' not a defined server-type'.format(_st))
    return


def get_have(api, module, server_types):
    """Get current configuration

    Args:
        api: AEDApi instance for this connection
        module: AnsibleModule instance
        server_types (dict): dict of serverType(str): id(int)

    Returns:
        A dict of the current state of the PG.
    """
    #  single rest GET call, return the dict...
    pg_name = module.params.get('pg_name')
    resp_code, raw_config = api.get_config(
        'protection-groups',
        query_params=dict(name=pg_name)
    )
    if resp_code in ResponseCodes.GOOD_RESP:
        pg_list = raw_config.get('protection-groups')
        if len(pg_list) is 0:
            # Need to create it..
            # Has requirements if new:
            if not (module.params.get('pg_protected_hosts') and
                    module.params.get('pg_server_type')):
                raise AEDAPIError('Protection Group "{}" does not exist, '
                                  'creating new PG requires pg_protected_hosts '
                                  'and pg_server_type defined.'.format(pg_name))
            return dict(
                pg_name="",
                pg_active=0,
                pg_protected_hosts=[],
                pg_server_type=0,
                pg_description="",
                pg_protection_level=None,
                pgid=-1
            )

        elif len(pg_list) is 1:
            ans_dict = rest_to_ans(pg_list[0], PARAM_MAP)

            # convert server type ID to server type name
            for _key, _val in server_types.items():
                if ans_dict['pg_server_type'] == _val:
                    ans_dict['pg_server_type'] = _key
                    break

            # rest protection_level of None is actually 'global'
            if ans_dict.get('pg_protection_level', "NOT THERE") is None:
                ans_dict['pg_protection_level'] = 'global'

            return ans_dict

        else:  # not good....
            raise AEDAPIError('Multiple PGs match name, '
                              'can only configure one at a time.')
    else:
        raise AEDAPIError('APIError: Failed fetching config. '
                          'response code:{}, response:{}'
                          .format(resp_code, raw_config))


def get_server_type_names(api):
    """Function to return dictionary of serverTypeNames: id (int)

    Args:
        api: AEDApi instance for this connection

    Returns:
        Dict of serverType(str): id(int)
    """
    resp_code, raw_config = api.get_config('protection-groups/server-types')

    st_dict = dict()
    if resp_code is 200:
        st_list = raw_config.get('server-types')
        for _st in st_list:
            st_dict[_st.get('serverName')] = _st.get('serverType')

    return st_dict


def main():
    """Module entry point"""

    argument_spec = dict(
        pg_name=dict(required=True, type='str'),
        pg_active=dict(type='bool'),
        pg_protected_hosts=dict(type='list'),
        pg_server_type=dict(type='str'),
        pg_description=dict(type='str'),
        pg_protection_level=dict(choices=['global', 'low', 'medium', 'high']),
        pg_present=dict(type='bool', default='True')
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    api = AEDAPIBase(Connection(module._socket_path))

    # Catch exceptions within the context and return
    # Ansible compliant error response.
    with exception_context(module, Exception):
        server_type_names = get_server_type_names(api)
        check_args(module, server_type_names)

        # Get what you want and have...
        have = get_have(api, module, server_type_names)
        want = get_want(module, PARAM_MAP)

        result = {'changed': False}

        # Determine if PG is to be deleted
        pg_present = module.params.get('pg_present')
        if pg_present is not None and not pg_present:
            if have['pgid'] == -1:  # Does not exist yet, will not exist.
                result['no_create'] = (
                    "{} does not exist and pg_present set to False.  Will not "
                    "bother creating to just remove it.".format(
                        want['pg_name']))

            else:  # Must be present, so delete it
                result['delete pg_name'] = '{}'.format(have['pg_name'])
                result['changed'] = True

                if not module.check_mode:
                    pgid = have['pgid']
                    resp_code, del_resp = api.delete_config(
                        command='protection-groups/{}/'.format(pgid))
                    if resp_code not in ResponseCodes.GOOD_DEL_RESP:
                        module.fail_json(msg='APIError: Did not delete {}. '
                                         'response code:{}, response:{}'
                                         .format(have['pg_name'], resp_code,
                                                 del_resp))

            module.exit_json(**result)

        changes = get_changes(have, want)
        if changes:
            if module._diff:
                result['diff'] = {'prepared': json.dumps(changes)}
            result['changed'] = True
            pgid = have['pgid']
            parsed_changes = ans_to_rest(changes, PARAM_MAP)
            if parsed_changes.get('serverType'):
                # Convert server type name to server type id
                parsed_changes['serverType'] = server_type_names.get(
                    parsed_changes.get('serverType'))

            if pgid == -1:
                if not module.check_mode:
                    # New PG
                    resp_code, new_config = api.create_config(
                        command='protection-groups/',
                        body_params=parsed_changes)
                    if resp_code not in ResponseCodes.GOOD_RESP:
                        module.fail_json(msg='APIError: response code:{}, '
                                         'response:{}'.format(resp_code, new_config))
                result['create pg_name'] = changes['pg_name']
            else:
                if not module.check_mode:
                    # Update PG
                    resp_code, new_config = api.push_config(
                        command='protection-groups/{}/'.format(pgid),
                        body_params=parsed_changes)
                    if resp_code not in ResponseCodes.GOOD_RESP:
                        module.fail_json(msg='APIError: response code:{}, '
                                         'response:{}'.format(resp_code, new_config))

        end_result = get_have(api, module, server_type_names)

    del end_result['pgid']

    result['aed_pg_state'] = end_result

    module.exit_json(**result)


if __name__ == '__main__':
    main()

#!/usr/bin/python

# Copyright: (c) 2019, NETSCOUT
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = """
---
module: aed_deployment
version_added: "2.7"
author: "Chris Hartmann, <ansible-aed@netscout.com>"
short_description: Manage the AED deployment state parameters
description:
  - Use this module to configure the deployment and operational parameters for AED
    devices.
notes:
  - This module supports check mode.
options:
  deployment_mode:
    description:
      - The deployment mode for an AED device.
    choices: ['monitor', 'inline', 'l3']
    required: false
    type: str

  protection_active:
    description:
      - Whether the protection mode for an AED device is active or inactive.
    required: false
    type: bool

  protection_level:
    description:
      - The protection level for an AED device.
    choices: ['low', 'medium', 'high']
    required: false
    type: str
"""

EXAMPLES = """
---
- name: set l3 mode
  aed_deployment:
    deployment_mode: l3
"""

RETURN = """
deployment_state:
  description: Returns the settings for the deployment mode, the protection mode,
    and the protection level.
  returned: always
  type: dict
  sample:
    {
        "deployment_mode": "inline",
        "protection_active": true,
        "protection_level": "high"
    }
"""

import json
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ansible.module_utils.network.aed.aed import (AEDAPIBase,
                                                  AEDAPIError,
                                                  check_args,
                                                  ans_to_rest,
                                                  rest_to_ans,
                                                  get_changes,
                                                  get_want,
                                                  ResponseCodes,
                                                  exception_context)


def morph_protection_level(var):
    """
    Convert a protection level to string if integer, or vice-versa
    """
    if type(var) is int:
        return ['low', 'medium', 'high'][var - 1]

    return ['low', 'medium', 'high'].index(var) + 1


def morph_protection_active(var):
    if type(var) is int:
        return True if var == 1 else False
    return 1 if var is True else 0


PARAM_MAP = [
    ('deployment_mode', 'deploymentMode', str),
    ('protection_active', 'protectionActive', morph_protection_active),
    ('protection_level', 'protectionLevel', morph_protection_level),
]


def get_have(api):
    #  single rest GET call, return the dict...
    resp_code, raw_config = api.get_config('summary')
    if resp_code == 200:
        return rest_to_ans(raw_config, PARAM_MAP)

    else:
        raise AEDAPIError('APIError: Failed fetching config. '
                          'response code:{}, response:{}'
                          .format(resp_code, raw_config))


def main():
    """
    Entry point for module execution
    """
    argument_spec = dict(
        deployment_mode=dict(choices=['monitor', 'inline', 'l3']),
        protection_active=dict(type='bool'),
        protection_level=dict(choices=['low', 'medium', 'high'])
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    with exception_context(module, Exception):
        connection = Connection(module._socket_path)

        api = AEDAPIBase(connection)

        warnings = list()
        check_args(module, warnings)
        result = {'changed': False}

        if warnings:
            result['warnings'] = warnings

        # Get what you want and have...
        want = get_want(module, PARAM_MAP)
        have = get_have(api)

        result = {'changed': False}

        # Determine if we need a change
        changes = get_changes(have, want)
        if changes:
            if module._diff:
                result['diff'] = {'prepared': json.dumps(changes)}
            result['changed'] = True
            parsed_changes = ans_to_rest(changes, PARAM_MAP)
            if not module.check_mode:
                resp_code, new_config = api.push_config(
                    command='summary',
                    body_params=parsed_changes
                )
                if resp_code not in ResponseCodes.GOOD_RESP:
                    module.fail_json(msg='APIError: response code:{}, '
                                     'response:{}'.format(resp_code,
                                                          new_config))

        result['deployment_state'] = get_have(api)

    module.exit_json(**result)


if __name__ == '__main__':
    main()

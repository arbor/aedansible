#!/usr/bin/python

# Copyright: (c) 2019, NETSCOUT
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: aed_general_settings
version_added: "2.7"
author: "Alan Saqui, <ansible-aed@netscout.com>"
short_description: Configure general settings for an AED device
description:
  - Use this module to configure the general settings on an AED device.
notes:
  - Untested
options:
  url_hostname:
    description:
      - The default URL hostname for an AED device.
    required: true
    type: str
"""

EXAMPLES = """
- name: Set the URL hostname:
    aed_general_settings:
      hostname: aed.example.com
"""

RETURN = """
aed_general_settings:
    description: Returns the current general settings.
    returned: always
    type: dict
    sample: {
      "blockHostNotificationInterval": 3600,
      "dateFormat": "mm/dd/yy",
      "maxProtectionGroups": 49,
      "topHostsEnable": true,
      "tzName": "Asia/Yakutsk",
      "uidleTimeout": 30,
      "urlHostName": "aed.example.com"
    }
"""

import json
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible.module_utils.network.aed.aed import (AEDAPIBase,
                                                  AEDAPIError,
                                                  ans_to_rest,
                                                  get_changes,
                                                  ResponseCodes,
                                                  exception_context)

PARAM_MAP = [
    ('url_hostname', 'urlHostName', str),
]


def get_general_settings(module, api):
    resp_code, response = api.get_config('general-settings')
    if resp_code not in ResponseCodes.GOOD_RESP:
        msg = "Could not get config for general settings (code: {}, resp: {})"
        raise AEDAPIError(msg.format(resp_code, response))
    return response


def update_config(module, api, cur_cfg):
    if module.check_mode:
        # Get current config and overlay the module parameters in order to
        # fake up an update.
        cur_cfg = get_general_settings(module, api)
        want = ans_to_rest(module.params, PARAM_MAP)
        cur_cfg.update(want)
        return cur_cfg

    body_params = ans_to_rest(module.params, PARAM_MAP)
    resp_code, response = api.push_config('general-settings',
                                          body_params=body_params)
    if resp_code not in ResponseCodes.GOOD_RESP:
        msg = "Could not push config (code: {}, resp: {})"
        raise AEDAPIError(msg.format(resp_code, response))
    return response


def main():
    """Main entry point for module execution."""
    argument_spec = dict(
        url_hostname=dict(type='str', required=True)
    )

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    connection = Connection(module._socket_path)
    api = AEDAPIBase(connection)

    with exception_context(module, Exception):
        cur_cfg = get_general_settings(module, api)
        new_cfg = update_config(module, api, cur_cfg)

        results = {'changed': True}
        changes = get_changes(cur_cfg, new_cfg)
        if not changes:
            results['changed'] = False
        else:
            if module._diff:
                results['diff'] = {'prepared': json.dumps(changes)}

        results['aed_general_settings'] = new_cfg

    module.exit_json(**results)


if __name__ == "__main__":
    main()

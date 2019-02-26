#!/usr/bin/python

# Copyright: (c) 2019, NETSCOUT
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: aed_smtp
version_added: "2.7"
author: "Alan Saqui, <ansible-aed@netscout.com>"
short_description: Manage AED SMTP relay server settings
description:
  - Use this module to configure the SMTP relay server settings for AED devices.
notes:
  - Untested
options:
  server:
    description:
      - The IP address of the SMTP relay server.
    type: str

  username:
    description:
      - The username for the SMTP relay server.
    type: str

  password:
    description:
      - The password for the SMTP relay server.
    type: str
"""

EXAMPLES = """
- name: Configure an SMTP server
    aed_smtp:
      server: 127.0.0.1

- name: Configure an SMTP server with credentials
    aed_smtp:
      server: 127.0.0.1
      username: admin
      password: admin
"""

RETURN = """
aed_smtp_state:
  description: Returns a tuple of the current SMTP relay server settings.
  returned: always
  type: dict
  sample:
    - {smtpPassword: "admin", smtpServer: "127.0.0.1", smtpUser: "admin"}
"""

import json
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible.module_utils.network.aed.aed import (AEDAPIBase,
                                                  AEDAPIError,
                                                  aed_argument_spec,
                                                  check_args,
                                                  ans_to_rest,
                                                  rest_to_ans,
                                                  get_changes,
                                                  get_want,
                                                  ResponseCodes,
                                                  exception_context)

PARAM_MAP = [
    ('server', 'smtpServer', str),
    ('username', 'smtpUser', str),
    ('password', 'smtpPassword', str),
]


def get_have(api):
    resp_code, raw_config = api.get_config('system/smtp')
    if resp_code == 200:
        return rest_to_ans(raw_config, PARAM_MAP)
    else:
        raise AEDAPIError(
            'APIError: Failed fetching config. '
            'response code:{}, response:{}'.format(
                resp_code, raw_config)
        )


def main():
    """Main entry point for module execution."""
    argument_spec = dict(
        server=dict(type='str'),
        username=dict(type='str'),
        password=dict(type='str', no_log=True),
    )

    argument_spec.update(aed_argument_spec)

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    with exception_context(module, Exception):
        connection = Connection(module._socket_path)

        api = AEDAPIBase(connection)

        warnings = list()
        check_args(module, warnings)
        result = {'changed': False}

        if warnings:
            result['warnings'] = warnings

        want = get_want(module, PARAM_MAP)
        have = get_have(api)

        result = {'changed': False}

        changes = get_changes(have, want)
        if changes:
            if module._diff:
                result['diff'] = {'prepared': json.dumps(changes)}
            result['changed'] = True
            if not module.check_mode:
                parsed_changes = ans_to_rest(changes, PARAM_MAP)
                resp_code, new_config = api.push_config(
                    command='system/smtp',
                    body_params=parsed_changes)
                if resp_code not in ResponseCodes.GOOD_RESP:
                    module.fail_json(msg='APIError: response code:{}, '
                                     'response:{}'.format(resp_code,
                                                          new_config))

    module.exit_json(**result)


if __name__ == "__main__":
    main()

#!/usr/bin/python

# Copyright: (c) 2019, NETSCOUT
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'network'
}

DOCUMENTATION = """
---
module: aed_remote_syslog
version_added: "2.7"
author: "Chris Hartmann, <ansible-aed@netscout.com>"
short_description: Manage the AED remote syslog settings
description:
  - Use this module to configure the remote syslog settings for AED devices.
notes:
  - Not Tested Yet

options:
  syslog_server:
    description:
      - The hostname or the IP address for the remote syslog server
    type: str

  syslog_port:
    description:
      - The port for communicating with the remote syslog server.
    type: int

  syslog_protocol:
    description:
      - The protocol for sending the syslog messages to the remote server.
    choices: ['udp', 'tcp']
    type: str

  syslog_format:
    description:
      - The format for the syslog messages.
    choices: ['cef', 'leef', 'legacy']
    type: str

  secure:
    description:
      - The secure TLS encrypted communication mode for the remote syslog
        communications.
    type: bool
"""

EXAMPLES = """
- name: set standard remote syslog server
  aed_remote_syslog:
    syslog_server: logserver.mynetwork.com
    syslog_port: 514
    syslog_protocol: udp
    syslog_format: legacy
    secure: False

- name: set secure TCP remote syslog server
  aed_remote_syslog:
    syslog_server: logserver.mynetwork.com
    syslog_port: 6514
    syslog_protocol: tcp
    syslog_format: legacy
    secure: True
"""

RETURN = """
aed_remote_syslog_state:
  description: Returns a tuple of the current remote syslog settings.
  returned: always
  type: list
  sample:
    - ['logserver.mynetwork.com', '514', 'udp', 'legacy', 'False']
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

# PARAM_MAP: list of tuples of ANSIBLE params, rest params and mutation method
# [ansible_param, rest_param, mutation]
PARAM_MAP = [
    ('syslog_server', 'host', str),
    ('syslog_port', 'port', str),
    ('syslog_protocol', 'protocol', str),
    ('syslog_format', 'format', str),
    ('secure', 'secure', bool)
]


def get_have(api):
    #  single rest GET call, return the dict...
    resp_code, raw_config = api.get_config('remote-syslog')
    if resp_code == 200:
        return rest_to_ans(raw_config, PARAM_MAP)

    else:
        raise AEDAPIError(
            'APIError: Failed fetching config. '
            'response code:{}, response:{}'.format(
                resp_code, raw_config)
        )


def main():
    """ main entry point for module execution
    """
    argument_spec = dict(
        syslog_server=dict(type='str'),
        syslog_port=dict(type='str'),
        syslog_protocol=dict(choices=['udp', 'tcp']),
        syslog_format=dict(choices=['cef', 'leef', 'legacy']),
        secure=dict(type='bool'),
    )

    argument_spec.update(aed_argument_spec)

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
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

        changes = get_changes(have, want)
        if changes:
            if module._diff:
                result['diff'] = {'prepared': json.dumps(changes)}
            result['changed'] = True
            if not module.check_mode:
                parsed_changes = ans_to_rest(changes, PARAM_MAP)
                resp_code, new_config = api.push_config(
                    command='remote-syslog',
                    body_params=parsed_changes
                )
                if resp_code not in ResponseCodes.GOOD_RESP:
                    module.fail_json(msg='APIError: response code:{}, '
                                     'response:{}'.format(resp_code,
                                                          new_config))
            result['aed_remote_syslog_state'] = get_have(api)

    module.exit_json(**result)


if __name__ == '__main__':
    main()

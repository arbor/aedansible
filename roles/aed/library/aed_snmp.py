#!/usr/bin/python

# Copyright: (c) 2019, NETSCOUT
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'network'}

DOCUMENTATION = """
---
module: aed_snmp
version_added: "2.7"
author: "Chris Hartmann, <ansible-aed@netscout.com>"
short_description: Manage the AED SNMP settings
description:
  - Use this module to configure the SNMP settings for an AED device.
notes:
  - Not Tested Yet
options:
  snmp_version:
    description:
      - Specifies the SNMP server version.
    choices: ['2', '3']
    type: str

  snmp_community:
    description:
      - (version 2 only) Specifies the community string to use for SNMP transactions.
    type: str

  snmp_username:
    description:
      - (version 3 only) Specifies the securityName to use for authenticated SNMPv3
        messages.
    type: str

  snmp_security_level:
    description:
      - (version 3 only) Sets the security level for the SNMP server.
    choices: ['noAuthNoPriv', 'authNoPriv', 'authPriv']
    type: str

  snmp_password:
    description:
      - (version 3 only) Specifies the password associated with username, to log into the SNMP server.
        Required if C(snmp_security_level) is set to C(authNoPriv) or C(authPriv).
    required: false
    type: str

  snmp_auth_proto:
    description:
      - (version 3 only) Sets the authentication protocol for
        the SNMP server.
    choices: ['md5', 'sha']
    type: str

  snmp_privacy_password:
    description:
      - (version 3 only) Specifies the privacy password for the authPriv security level.
    type: str

  snmp_privacy_protocol:
    description:
      - (version 3 only) Sets the privacy protocol for the SNMP server.
    choices: ['aes', 'des']
    type: str

"""

EXAMPLES = """
- name: set SNMP v2 parameters
  aed_snmp:
    snmp_version: 2
    snmp_community: thisIsTheCommunityString

- name: set SNMP v3 parameters
  aed_snmp:
    snmp_version: 3
    snmp_username: snmpUser
    snmp_security_level: authPriv
    snmp_password: snmpPassword
    snmp_auth_proto: SHA
    snmp_privacy_password: snmpPrivacy
    snmp_privacy_protocol: AES
"""

RETURN = """
aed_remote_syslog_state:
  description: Returns the current remote syslog settings.
  returned: always
  type: list
  sample:
    - ['logserver.mynetwork.com', '514', 'udp', 'False']
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
    ('snmp_version', 'version', int),
    ('snmp_community', 'community', str),
    ('snmp_username', 'username', str),
    ('snmp_security_Level', 'securityLevel', str),
    ('snmp_password', 'password', str),
    ('snmp_auth_proto', 'authProto', str),
    ('snmp_privacy_password', 'privacyPassword', str),
    ('snmp_privacy_protocol', 'privacyProto', str)
]


def get_have(api):
    #  single rest GET call, return the dict...
    resp_code, raw_config = api.get_config('snmp')
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
        snmp_version=dict(type='str', choices=['2', '3']),
        snmp_community=dict(type='str', no_log=True),
        snmp_username=dict(type='str'),
        snmp_security_level=dict(
            type='str', choices=['noAuthNoPriv', 'authNoPriv', 'authPriv']),
        snmp_password=dict(type='str', no_log=True),
        snmp_auth_proto=dict(type='str', choices=['md5', 'sha']),
        snmp_privacy_password=dict(type='str', no_log=True),
        snmp_privacy_protocol=dict(choices=['aes', 'des']),
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
                    command='snmp',
                    body_params=parsed_changes)
                if resp_code not in ResponseCodes.GOOD_RESP:
                    module.fail_json(msg='APIError: response code:{}, '
                                     'response:{}'.format(resp_code,
                                                          new_config))

    module.exit_json(**result)


if __name__ == '__main__':
    main()

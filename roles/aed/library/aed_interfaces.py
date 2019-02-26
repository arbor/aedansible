#!/usr/bin/python

# Copyright: (c) 2019, NETSCOUT
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: aed_interfaces
version_added: "2.7"
author: "Steve William, <ansible-aed@netscout.com>"
short_description: Manage AED interfaces
description:
  - Use this module to manage interfaces and their relevant configurations on AED devices.
notes:
  - This module supports check mode.
options:
  link_propagation_up_timeout:
    description:
      - An integer that specifies the number of seconds to wait before
        propagating the "<up>" link state. Do not use with the name option.
    type: int

  link_propagation_down_timeout:
    description:
      - An integer that specifies the number of seconds to wait before
        propagating the "<down>" link state. Do not use with the name option.
    type: int

  name:
    description:
      - Name of the interface.
    type: str
  addr:
    description:
      - A CIDR block <A.B.C.D/M>.
    type: str
  addr_present:
    description:
      - Determine if the address exists. Set to false to remove the address.
    default: true
    type: bool
"""

EXAMPLES = """
---
- name: Setup link state propagation timeouts
  aed_interfaces:
    link_propagation_up_timeout: 2
    link_propagation_down_timeout: 5

- name: Setup int0
  aed_interfaces:
    name: int0
    addr: 10.20.30.0/24

- name: Setup ext0
  aed_interfaces:
    name: ext0
    addr: 20.20.30.0/24
"""

RETURN = """
aed_interface_state:
  description: Returns the interface configuration.
  returned: always
  type: dict
  sample:
    - {
        "link_propagation_up_timeout": "2",
        "link_propagation_down_timeout": "10",
      }
    - {
        "addr": "22.20.30.0/24",
        "name": "ext0"
      }

changed:
  description: Returns a Boolean that indicates if any changes were made to the interface.
  type: Boolean
  returned: always

add_interface_address:
    description: Returns the name of the interface and the address that was added.
    type: dict
    returned: When an address is added to an interface.

delete_interface_address:
    description: Returns the name of the interface and the address that was deleted.
    type: dict
    returned: When an address is deleted from an interface.

no_delete:
    description: Returns this message when addr_present is set to false
                 for an interface address that does not exist.
    type: str
    returned: When trying to remove a non-existent address.
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

PARAM_MAP = [
    ('link_propagation_up_timeout', 'linkPropagationUpTimeout', int),
    ('link_propagation_down_timeout', 'linkPropagationDownTimeout', int),
    ('name', 'interfaceName', str),
    ('addr', 'address', str)]

LP_PARAM_MAP = [
    ('link_propagation_up_timeout', 'linkPropagationUpTimeout', int),
    ('link_propagation_down_timeout', 'linkPropagationDownTimeout', int)]

INTF_PARAM_MAP = [
    ('name', 'interfaceName', str),
    ('addr', 'address', str)]


def get_have(api, module):
    """Get current configuration

    Args:
        api (AEDApi): AEDApi instance for this connection
        module (AnsibleModule): AnsibleModule instance

    Returns:
        A dict of the current state of the interfaces.
    """
    # This task is probably setting the
    # link state propagation timeouts
    if not module.params.get('name'):
        # Get all information about interfaces
        resp_code, raw_config = api.get_config('mitigation-interfaces')
        if resp_code in ResponseCodes.GOOD_RESP:
            timeouts = rest_to_ans(raw_config, LP_PARAM_MAP)
            return timeouts
        else:
            raise AEDAPIError('APIError: Failed fetching config. '
                              'response code:{}, response:{}'
                              .format(resp_code, raw_config))
    else:
        intf_name = module.params.get('name')
        resp_code, raw_config = api.get_config('mitigation-interfaces/{}/'.format(intf_name))
        if resp_code in ResponseCodes.GOOD_RESP:
            intf = rest_to_ans(raw_config, INTF_PARAM_MAP)
            return intf
        else:
            raise AEDAPIError('APIError: Failed fetching config. '
                              'response code:{}, response:{}'
                              .format(resp_code, raw_config))


def main():
    """Program entry point"""
    argument_spec = dict(
        name=dict(type='str'),
        link_propagation_up_timeout=dict(type='int'),
        link_propagation_down_timeout=dict(type='int'),
        addr=dict(type='str'),
        addr_present=dict(type='bool', default='True')
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    api = AEDAPIBase(Connection(module._socket_path))

    result = {'changed': False}

    with exception_context(module, Exception):
        have = get_have(api, module)
        want = get_want(module, PARAM_MAP)
        changes = get_changes(have, want)
        intf_name = module.params.get('name', None)
        intf_addr = module.params.get('addr', None)
        addr_present = module.params.get('addr_present')
        if not addr_present:
            changes['addr_present'] = False
        # Run only if there are any changes and
        # check mode is off.
        if changes:
            if not intf_name:
                if module._diff:
                    result['diff'] = {'prepared': json.dumps(changes)}
                parsed_changes = ans_to_rest(changes, LP_PARAM_MAP)
                if not module.check_mode:
                    resp_code, new_config = api.push_config(command='mitigation-interfaces',
                                                            body_params=parsed_changes)
                    if resp_code not in ResponseCodes.GOOD_RESP:
                        module.fail_json(msg='APIError: Failed pushing config. '
                                         'response code:{}, response:{}'
                                         .format(resp_code, new_config))
                result['changed'] = True
            else:
                parsed_changes = ans_to_rest(changes, INTF_PARAM_MAP)
                if not addr_present:
                    # Check if the interface has the specified address
                    # and delete it. If not, don't create just for the
                    # sake of deleting it.
                    if have['addr']:
                        if not module.check_mode:
                            resp_code, new_config = api.delete_config(command='mitigation-interfaces/{}/{}/'
                                                                      .format(intf_name, intf_addr))
                            if resp_code not in ResponseCodes.GOOD_DEL_RESP:
                                module.fail_json(msg='APIError: Failed deleting config. '
                                                 'response code: {}, response: {}'
                                                 .format(resp_code, new_config))
                        result['changed'] = True
                        result['delete_interface_address'] = {intf_name: intf_addr}
                    else:
                        result['no_delete'] = ('This interface does not have an address set. '
                                               'Not creating address to only delete it.')
                else:
                    if module._diff:
                        result['diff'] = {'prepared': json.dumps(changes)}
                    if not module.check_mode:
                        resp_code, new_config = api.push_config(command='mitigation-interfaces/{}/'.format(intf_name),
                                                                body_params=parsed_changes)
                        if resp_code not in ResponseCodes.GOOD_RESP:
                            module.fail_json(msg='APIError: Failed pushing config. '
                                             'response code: {}, response: {}'
                                             .format(resp_code, new_config))
                    result['changed'] = True
                    result['add_interface_address'] = {intf_name: intf_addr}
            new_state = get_have(api, module)
            result['aed_interface_state'] = new_state
    module.exit_json(**result)


if __name__ == '__main__':
    main()

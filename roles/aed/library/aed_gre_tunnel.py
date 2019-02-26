#!/usr/bin/python

# Copyright: (c) 2019, NETSCOUT
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: aed_gre_tunnel
version_added: "2.7"
author: "Alan Saqui, <ansible-aed@netscout.com>"
short_description: Manage AED GRE tunnels
description:
  - Use this module to configure GRE tunnels on an AED device.
notes:
  - Not tested yet
options:
  interface:
    description:
      - The name of the interface to configure the GRE tunnel on.
    required: true
    type: str
  state:
    description:
      - Whether to add or remove the GRE tunnel.
    choices: ['present', 'absent']
    default: present
    type: str
  remote_ips:
    description:
      - A comma-delimited list of source IP addresses.
    type: str
  local_ip:
    description:
      - The local IP address for the external interface.
    type: str
  subnet_length:
    description:
      - The length of the subnet (in bits) for the local IP address.
    type: int
"""

RETURN = """
aed_gre_tunnel_state:
  description: Returns the current GRE tunnel settings for the given interface.
  returned: always
  type: dict
  sample: {
    "greRemoteIps": [
      "1.1.1.1",
      "2.2.2.2"
    ],
    "interface": "ext0",
    "localIp": "192.168.1.1",
    "subnetBitLength": 24
  }
"""

import json
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible.module_utils.six.moves.urllib.parse import urljoin

from ansible.module_utils.network.aed.aed import (AEDAPIBase,
                                                  AEDAPIError,
                                                  aed_argument_spec,
                                                  ans_to_rest,
                                                  get_changes,
                                                  ResponseCodes,
                                                  exception_context)

PARAM_MAP = [
    ('interface', 'interface', str),
    ('remote_ips', 'greRemoteIps', list),
    ('local_ip', 'localIp', str),
    ('subnet_length', 'subnetBitLength', int),
]


def get_interface_config(module, api):
    intf_name = module.params['interface']
    url = urljoin('gre-tunnels/', '{}'.format(intf_name))
    resp_code, response = api.get_config(url)
    if resp_code not in ResponseCodes.GOOD_RESP:
        # XXX: The API can return different status codes for an invalid
        # interface (422, 500), instead of just returning a 404. Since we can't
        # differentiate between 'interface not found' and 'an error occurred'
        # we'll just punt if the user gives an invalid interface.
        msg = "Could not get config for interface '{}' (code: {}, resp: {})"
        raise AEDAPIError(msg.format(intf_name, resp_code, response))

    return response


def has_gre_tunnel(module, api, intf):
    resp_code, response = api.get_config('gre-tunnels')
    if resp_code not in ResponseCodes.GOOD_RESP:
        msg = "Could not delete config (code: {}, resp: {})"
        raise AEDAPIError(msg.format(resp_code, response))

    gre_tunnels = response.get('gre-tunnels', [])
    for tun in gre_tunnels:
        if tun.get('interface', None) == intf:
            return True
    return False


def delete_config(module, api, cur_cfg):
    if module.check_mode:
        # If you delete the config, everything but the interface name is nulled
        # out. Example:
        # {
        #   "greRemoteIps": null,
        #   "interface": "ext0",
        #   "localIp": null,
        #   "subnetBitLength": null
        # }
        # Fake up a DELETE response by creating a new config with all of the
        # parameters nulled out except for the interface name.
        want = {k[1]: None for k in PARAM_MAP}
        want['interface'] = module.params['interface']
        return want

    intf_name = module.params['interface']
    if not has_gre_tunnel(module, api, intf_name):
        return cur_cfg

    url = urljoin('gre-tunnels/', '{}'.format(intf_name))
    resp_code, response = api.delete_config(url)
    if resp_code not in ResponseCodes.GOOD_DEL_RESP:
        msg = "Could not delete config (code: {}, resp: {})"
        raise AEDAPIError(msg.format(resp_code, response))

    return get_interface_config(module, api)


def update_config(module, api, cur_cfg):
    if module.check_mode:
        # Get the current config and overlay the module parameters in order to
        # 'fake' an update.
        new_cfg = dict(cur_cfg)
        want = ans_to_rest(module.params, PARAM_MAP)
        new_cfg.update(want)
        return new_cfg

    body_params = ans_to_rest(module.params, PARAM_MAP)
    # Remove the 'interface' key as it should not be included in the param
    # list.
    del body_params['interface']
    if not body_params:
        # If body_params is empty, we aren't changing anything, so just return
        # the current config as the new config.
        return cur_cfg
    url = urljoin('gre-tunnels/', '{}'.format(module.params['interface']))
    # XXX: We're always using POST here, as it seems to work in every case that
    # PATCH would work.
    resp_code, response = api.create_config(url, body_params=body_params)
    if resp_code not in ResponseCodes.GOOD_RESP:
        msg = "Could not post new config (code: {}, resp: {})"
        raise AEDAPIError(msg.format(resp_code, response))
    return response


def main():
    argument_spec = dict(
        interface=dict(type='str', required=True),
        state=dict(choices=['present', 'absent'], default='present'),
        remote_ips=dict(type='list'),
        local_ip=dict(type='str'),
        subnet_length=dict(type='int')
    )

    argument_spec.update(aed_argument_spec)

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_together=(
            ('local_ip', 'remote_ips', 'subnet_length'),
        ),
    )

    api = AEDAPIBase(Connection(module._socket_path))

    with exception_context(module, Exception):
        cur_cfg = get_interface_config(module, api)
        if module.params.get('state') == 'absent':
            new_cfg = delete_config(module, api, cur_cfg)
        else:
            new_cfg = update_config(module, api, cur_cfg)

        result = {'changed': False}
        changes = get_changes(cur_cfg, new_cfg)
        if changes:
            result['changed'] = True
        if module._diff:
            result['diff'] = {'prepared': json.dumps(changes)}
        result['aed_gre_tunnel_state'] = new_cfg
        module.exit_json(**result)


if __name__ == "__main__":
    main()

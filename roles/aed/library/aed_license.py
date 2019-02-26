#!/usr/bin/python

# Copyright: (c) 2019, NETSCOUT
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: aed_license
version_added: "2.7"
author: "Steve William, <ansible-aed@netscout.com>"
short_description: Manage AED licenses.
description:
  - Use this module to manage the AED licenses.
notes:
  - This module supports check mode.
options:
  server_id:
    description:
      - The ID for the cloud-based license server.
    required: false
    type: str

  capability:
    description:
      - The license type.
    choices: ['throughput', 'aif']
    required: false
    type: str

  requested:
    description:
      - The requested license limit. Required only when a capability is set.
    required: false
    type: str
"""

EXAMPLES = """
---
- name: Set the license server
  aed_license:
    server_id: ABCDEFGHIJKL

- name: Request the throughput amount
  aed_license:
    capability: throughput
    requested: 100

- name: Request an AIF advanced license
  aed_license:
    capability: aif
    requested: advanced
"""

RETURN = """
aed_license_state:
  description: Returns a dictionary of the license configuration.
  returned: always
  type: dict
  sample:
    - {
      "server_id": "K5BLZYXMU1R7"
      }
    - {
      "capability": "throughput",
      "expiration": "1580428799",
      "granted": "500",
      "requested": "500"
      }
    - {
      "capability": "aif",
      "expiration": "1580428799",
      "granted": "advanced",
      "requested": "advanced"
      }

changed:
  description: Returns a value that indicates if any changes were made to the license configuration.
  type: bool
  returned: always
"""

import json
import signal
from time import sleep
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


def morph_requested_capability(var):
    """Return value as string or integer based on type

    Args:
        var (str):

    Return
    """
    if isinstance(var, int):
        return str(var)
    elif var in ['advanced']:
        return str(var)
    elif var in ['none']:
        return None
    else:
        return int(var)


SERVER_PARAM_MAP = [
    ('server_id', 'serverId', str)]

CAPABILITIES_PARAM_MAP = [
    ('capability', 'capability', str),
    ('requested', 'requested', morph_requested_capability),
    ('granted', 'granted', morph_requested_capability),
    ('expiration', 'expiration', str)]

BASE_URI = 'license'


def verify_response(resp_code, config, err_msg='Unsuccessful response',
                    expected_codes=ResponseCodes.GOOD_RESP):
    """Check if the correct response code was received.

    Args:
        resp_code (int): Response code received
        config (dict): Response content
        err_msg (str): Custom error message
        expected_codes (list): List of codes to match against

    Return:
        True on success, fail on error
    """
    if resp_code not in expected_codes:
        raise AEDAPIError('APIError: {}. '
                          'response code:{}, response:{}'
                          .format(err_msg, resp_code, config))
    return


def get_have(api, module):
    """Get current configuration

    Args:
        api (AEDApi): AEDApi instance for this connection
        module (AnsibleModule): AnsibleModule instance

    Returns:
        A dict of the current state of the AED License.
    """
    have = {}
    lic_server_id = module.params.get('server_id', None)
    capability = module.params.get('capability', None)
    if lic_server_id or not (lic_server_id or capability):
        # Get license server config
        url = BASE_URI + '/server/'
        resp_code, raw_config = api.get_config(url)
        verify_response(resp_code, raw_config)
        have.update(rest_to_ans(raw_config, SERVER_PARAM_MAP))

    if capability or not (lic_server_id or capability):
        # Get license capabilities config
        url = BASE_URI + '/capabilities/'
        resp_code, raw_config = api.get_config(url)
        verify_response(resp_code, raw_config)
        capabilities = []
        for cap in raw_config['capabilities']:
            if cap['capability'] == capability or \
                    not (lic_server_id or capability):
                capabilities.append(rest_to_ans(cap, CAPABILITIES_PARAM_MAP))
        have['capabilities'] = capabilities
    return have


def main():
    """Module entry point"""

    argument_spec = dict(
        server_id=dict(type='str'),
        capability=dict(type='str'),
        requested=dict(type='str'))

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    api = AEDAPIBase(Connection(module._socket_path))

    def wait_for_changes(api):
        """Wait before panicking, requests can take
        some time to complete.

        Args:
            api (AEDApi): AEDApi instance for this connection

        Return:
            Error on time out, else true
        """
        # The /license/ API endpoints make requests to the
        # license server and the license server processes
        # this request. The API provides endpoints to
        # check the status of the request.
        # To make sure the task was competed, we much check
        # status of the request and timeout if it wasn't in
        # a given time frame. This does not mean that the
        # request will not be successful. It only prevents
        # Ansible from waiting indefinitely.

        def _sig_alarm(sig, tb):
            raise AEDAPIError('Timed out waiting 90s for license server'
                              ' to complete request. The request may or'
                              ' may not have completed successfully.')

        timeout = 90
        signal.signal(signal.SIGALRM, _sig_alarm)
        signal.alarm(timeout)
        while True:
            resp_code, response = api.get_config(command=BASE_URI + '/progress/')
            if resp_code in ResponseCodes.GOOD_RESP:
                # Check if the request is completed
                if response['status'].upper() in ['COMPLETED.']:
                    return
            sleep(2)

    # Catch exceptions within the context and return
    # Ansible compliant error response.
    with exception_context(module, Exception):
        have = get_have(api, module)
        result = {'changed': False}
        diff = {}
        if module.params.get('server_id', None):
            want = get_want(module, SERVER_PARAM_MAP)
            changes = get_changes(have, want)
            parsed_changes = ans_to_rest(changes, SERVER_PARAM_MAP)
            if changes:
                if not module.check_mode:
                    if not have['server_id']:
                        # PUT request if no lic server is configured
                        resp_code, new_config = api.put_config(
                            command=BASE_URI + '/server/',
                            body_params=parsed_changes)
                    else:
                        # PATCH request if lic server is to be modified
                        resp_code, new_config = api.push_config(
                            command=BASE_URI + '/server/',
                            body_params=parsed_changes)
                    verify_response(resp_code, new_config)
                    wait_for_changes(api)
                result['changed'] = True
                diff.update(changes)
        if module.params.get('capability', None):
            want = get_want(module, CAPABILITIES_PARAM_MAP)
            requested = module.params.get('requested', None)
            parsed_changes = ans_to_rest(want, CAPABILITIES_PARAM_MAP)
            parsed_changes.pop('capability')
            capability = module.params.get('capability', None)
            # Make changes only if the requested
            # capability hasn't already been granted
            if have['capabilities'][0]['granted'] != requested:
                if not module.check_mode:
                    resp_code, new_config = api.put_config(
                        command=BASE_URI + '/capabilities/{}/'.format(capability),
                        body_params=parsed_changes)
                    verify_response(resp_code, new_config)
                    wait_for_changes(api)
                result['changed'] = True
                diff.update(want)
        if module._diff:
            result['diff'] = {'prepared': json.dumps(diff)}
        # In check mode, `aed_license_state` key will still show the unchanged state.
        # Though, `what_changed` will show the expected changes.
        result['aed_license_state'] = get_have(api, module)
        module.exit_json(**result)


if __name__ == '__main__':
    main()

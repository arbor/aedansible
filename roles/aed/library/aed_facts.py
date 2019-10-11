#!/usr/bin/python

# Copyright: (c) 2019, NETSCOUT
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: aed_facts
version_added: "2.7"
author: "Chris Hartmann, <ansible-aed@netscout.com>"
short_description: Collect facts about AED devices
description:
  - Use this module to collect all of the facts or specific subsets of facts about AED devices.
options:
  gather_subset:
    description:
      - Restricts the facts that are collected to a given subset.
        Use C(M(!)) before a subset name if you do not want to collect facts for that subset.
    choices: [
      'device_info'
      'general_settings',
      'operational_status',
      'protection_groups',
      'server_types',
      'license',
      'interfaces',
      'smtp',
      'gre_tunnels',
      'all'
    ]
    required: false
    default: 'all'
    version_added: "2.7"
    type: str
"""

EXAMPLES = """
---
- name: Collect all of the facts
  aed_facts:
    gather_subset:
      - all

# Collect only the configuration and general_settings facts
- aed_facts:
    gather_subset:
      - general_settings

# Do not collect the operational status facts
- aed_facts:
    gather_subset:
      - "!operational_status"
"""

RETURN = """
aed_gather_subset:
  description: Returns a list of the fact subsets that were collected from an AED device.
  returned: always
  type: list

# aed_info
aed_hardware:
  description: Returns the hardware information for the AED device.
  returned: always
  type: str
aed_packages:
  description: Returns information on the ArbOS and AED packages installed on the  AED device.
  returned: always
  type: str

# aed_operational_status
aed_deployment_mode:
  description: Returns the deployment mode for an AED device.
  returned: always
  type: str
aed_protection_active:
  description: Returns the protection mode for an AED device.
  returned: always
  type: str
aed_protection_level:
  description: Returns the protection level for an AED device.
  returned: always
  type: str

# aed_protection_groups
aed_protection_groups:
    description: Returns a list of the protection groups on an AED device.
    returned: always
    type: list

# aed_license
aed_license:
    description: Returns the configured server ID and capabilities.
    returned: always
    type: list

# aed_interfaces
aed_interfaces:
    description: Returns a list of interfaces and their configurations.
    returned: always
    type: list
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible.module_utils.six import iteritems

from ansible.module_utils.network.aed.aed import (AEDAPIBase,
                                                  AEDAPIError,
                                                  check_args,
                                                  rest_to_ans,
                                                  exception_context,
                                                  ARBOS_VERSION_RE,
                                                  BUILD_RE,
                                                  AED_VERSION_RE)


class FactsBase(object):
    def __init__(self, module):
        self.module = module
        self.warnings = list()
        self.facts = dict()

        connection = Connection(module._socket_path)

        self.api = AEDAPIBase(connection)

    def populate(self):
        pass

    def get_config(self, command):
        #  single rest GET call, return the dict...
        resp_code, raw_config = self.api.get_config(command)
        if resp_code == 200:
            return raw_config

        else:
            raise AEDAPIError(
                'APIError: Failed fetching config. '
                'response code:{}, response:{}'.format(
                    resp_code, raw_config)
            )

    def get_server_types(self):
        """
        Function to return dictionary of serverTypeNames: id (int)
        :param api: AEDApi instance for this connection
        :return:
        dict of serverType(str): id(int)
        """
        resp_code, raw_config = self.api.get_config(
            'protection-groups/server-types')

        st_dict = dict()
        if resp_code is 200:
            st_list = raw_config.get('server-types')
            for st in st_list:
                st_dict[st.get('serverType')] = st.get('serverName')

        return st_dict


class DeviceInfo(FactsBase):
    def populate(self):
        hardware_cfg = self.get_config('system/hardware')
        packages_cfg = self.get_config('system/packages')
        packages_ret = {'arbos': {}, 'aed': {}}
        for _key, _val in packages_cfg.items():
            if 'ARBOS' in _key.upper():
                packages_ret['arbos']['arch'] = _val['arch']
                packages_ret['arbos']['version'] = ARBOS_VERSION_RE.search(
                    _val['comment']).group(1)
                packages_ret['arbos']['build'] = BUILD_RE.search(
                    _val['comment']).group(1)
            elif 'ARBOR-EDGE-DEFENSE' in _key.upper():
                packages_ret['aed']['arch'] = _val['arch']
                packages_ret['aed']['version'] = AED_VERSION_RE.search(
                    _val['comment']).group(1)
                packages_ret['aed']['build'] = BUILD_RE.search(
                    _val['comment']).group(1)
        self.facts['aed_hardware'] = hardware_cfg
        self.facts['aed_packages'] = packages_ret


class OperationalStatus(FactsBase):
    def morph_protection_level(self, var):
        """
        Convert a protection level to string if integer, or vice-versa
        """

        if type(var) is int:
            return ['low', 'medium', 'high'][var - 1]

        return ['low', 'medium', 'high'].index(var) + 1

    def morph_protection_active(self, var):
        if type(var) is int:
            return True if var == 1 else False
        return 1 if var is True else 0

    def populate(self):
        param_map = [
            ('deployment_mode', 'deploymentMode', str),
            ('protection_active', 'protectionActive',
                self.morph_protection_active),
            ('protection_level', 'protectionLevel',
                self.morph_protection_level),
        ]
        self.facts.update(
            rest_to_ans(self.get_config('summary'), param_map)
        )


class ProtectionGroups(FactsBase):
    def morph_pg_active(self, var):
        if type(var) is int:
            return True if var == 1 else False
        return 1 if var is True else 0

    def morph_pg_protection_level(self, var):
        """
        Convert a protection level to string if integer, or vice-versa
        """
        if var is None:
            return 'global'

        if type(var) is int:
            return ['low', 'medium', 'high'][var - 1]

        if var == 'global':
            return None

        return ['low', 'medium', 'high'].index(var) + 1

    def morph_server_types(self, var):
        if type(var) is int:
            server_types = self.get_server_types()
            return server_types[var]

        return var

    def populate(self):
        param_map = [
            ('pg_name', 'name', str),
            ('pg_active', 'active', self.morph_pg_active),
            ('pg_protected_hosts', 'prefixes', list),
            ('pg_server_type', 'serverType', self.morph_server_types),
            ('pg_description', 'description', str),
            ('pg_protection_level', 'protectionLevel',
             self.morph_pg_protection_level),
            ('pgid', 'pgid', int)
        ]

        all_pgs = self.get_config('protection-groups').get('protection-groups')

        pg_list = []
        for pg in all_pgs:
            pg_list.append(rest_to_ans(pg, param_map))

        self.facts.update({'aed_protectiongroups': pg_list})

        return


class ServerTypes(FactsBase):

    def pl_rest_to_ans(self, rest_dict, param_map):
        ans_dict = dict()

        for setting, setting_param_map in param_map:
            setting_dict = rest_dict.get(setting)
            if setting_dict is None:
                continue

            for ans_key, rest_key, func in setting_param_map:
                val = setting_dict.get(rest_key)
                if val is not None:
                    if func:
                        val = func(val)

                ans_dict[ans_key] = val

        return ans_dict

    def populate(self):
        param_map = [
            ('name', 'serverName', str),
            ('server_type', 'serverType', int),
            ('http_reporting', 'httpReporting', bool),
            ('profilling', 'profiling', bool),
            ('profiling_duration', 'profilingDuration', int),
            ('profiling_start', 'profilingStart', int),
            ('stix_enabled', 'stixEnabled', None),
        ]
        p_levels = ['protection_level_high', # noqa
                    'protection_level_low',
                    'protection_level_medium']
        p_level_map = [('appbehavior',
                        [('appbehavior_interrupt_count', 'interruptCnt', int)]),
                       ('botnet',
                        [('botnet_basic', 'basic', bool),
                         ('botnet_segment', 'segment', bool),
                         ('botnet_signatures', 'signatures', bool)]),
                       ('connlimit',
                        [('connection_limit_enabled', 'enabled', bool)]),
                       ('detectIcmp',
                        [('detect_icmp_enabled', 'enabled', bool),
                         ('detect_icmp_bps', 'icmpBps', int),
                         ('detect_icmp_rate', 'icmpRate', int)]),
                       ('detectSyn',
                        [('detect_syn_flood_enabled', 'enabled', bool),
                         ('detect_syn_flood_delta_rate', 'synAckDeltaRate',
                          int),
                         ('detect_syn_flood_rate', 'synRate', int)]),
                       ('dnsAuth',
                        [('dns_auth_enable', 'enabled', bool)]),
                       ('dnsMalform',
                        [('dns_malform_enable', 'enabled', bool)]),
                       ('dnsNxdomain',
                        [('dns_nx_domain_rate', 'rate', int)]),
                       ('dnsQuery',
                        [('dns_query_rate', 'rate', int)]),
                       ('dnsRegex',
                        [('dns_regex_list', 'statement', list)]),
                       ('filter',
                        [('filter_list', 'statement', list)]),
                       ('fragmentation',
                        [('fragmentation_detection_enabled', 'enabled', bool),
                         ('fragmentation_detection_bps', 'bps', int),
                         ('fragmentation_detection_pps', 'pps', int)]),
                       ('httpMalform',
                        [('http_malform_enabled', 'enabled', bool)]),
                       ('httpProxyDetect',
                        [('http_proxy_detect_enabled', 'enabled', bool)]),
                       ('httpRatelimit',
                        [('http_rate_limit_object_rate', 'objectRate', int),
                         ('http_rate_limit_request_rate', 'requestRate', int)]),
                       ('httpRegex',
                        [('http_regex_list', 'statement', list)]),
                       ('idleReset',
                        [('idle_reset_enabled', 'enabled', bool),
                         ('idle_reset_bit_rate', 'bitRate', int),
                         ('idle_reset_idle_timeout', 'idleTimeout', int),
                         ('idle_reset_init_size', 'initSize', int),
                         ('idle_reset_init_timeout', 'initTimeout', int),
                         ('idle_reset_num_idles', 'numIdles', int),
                         ('idle_reset_track_long_lived', 'trackLongLived',
                          bool)]),
                       ('multicast',
                        [('multicast_enabled', 'enabled', bool)]),
                       ('privateAddress',
                        [('private_addresses_enabled', 'enabled', bool)]),
                       ('regex',
                        [('regex_enabled', 'enabled', bool),
                         ('regex_blacklist_enable', 'blacklistEnable', bool),
                         ('regex_include_headers', 'includeHeaders', bool),
                         ('regex_match_source_port', 'matchSrcPort', bool),
                         ('regex_pattern', 'pattern', list),
                         ('regex_tcp_ports', 'tcpPorts', list),
                         ('regex_udp_ports', 'udpPorts', list)]),
                       ('reputation',
                        [('reputation_enabled', 'enabled', bool),
                         ('reputation_asert_confidence', 'asertConfidence',
                          str),
                         ('reputation_categories', 'categories', dict),
                         ('reputation_custom_confidence', 'customConfidence',
                          str),
                         ('reputation_use_custom', 'useCustom', bool)]),
                       ('shaping',
                        [('shaping_enabled', 'enabled', bool),
                         ('shaping_bps', 'bps', int),
                         ('shaping_filter', 'filter', list),
                         ('shaping_pps', 'pps', int)]),
                       ('sipMalform',
                        [('sip_malform_enabled', 'enabled', bool)]),
                       ('sipRequest',
                        [('sip_request_rate', 'rate', int)]),
                       ('synAuth',
                        [('syn_auth_enabled', 'enabled', bool),
                         ('syn_auth_automation_enabled', 'automationEnabled',
                          bool),
                         ('syn_auth_automation_threshold',
                          'automationThreshold', bool),
                         ('syn_auth_destination_ports', 'dstPorts', list),
                         ('syn_auth_http_auth_enabled', 'httpAuthEnabled',
                          bool),
                         ('syn_auth_javascript_enabled', 'javascriptEnabled',
                          bool),
                         ('syn_auth_out_of_sequence_enabled', 'outOfSeqEnabled',
                          bool),
                         ('syn_auth_soft_reset_enabled', 'softResetEnabled',
                          bool)]),
                       ('tlsMalform',
                        [('tls_malfom_enabled', 'enabled', bool)]),
                       ('udpFlood',
                        [('udp_flood_enabled', 'enabled', bool),
                         ('udp_flood_bps', 'bps', int),
                         ('udp_flood_pps', 'pps', int)]),
                       ('webcrawler',
                        [('webcrawler_enabled', 'enabled', bool)]),
                       ('zombie',
                        [('zombie_bps', 'bps', int),
                         ('zombie_pps', 'pps', int)])
                       ]

        all_sts = self.get_config('protection-groups/server-types').get(
            'server-types')
        st_list = []
        for st_rest in all_sts:
            st_config = rest_to_ans(st_rest, param_map)
            st_config['protection_level_high'] = self.pl_rest_to_ans(
                st_rest['protectionLevels']['high'], p_level_map
            )
            st_config['protection_level_low'] = self.pl_rest_to_ans(
                st_rest['protectionLevels']['low'], p_level_map
            )
            st_config['protection_level_medium'] = self.pl_rest_to_ans(
                st_rest['protectionLevels']['medium'], p_level_map
            )

            st_list.append(st_config)

        self.facts.update({'aed_server_types': st_list})

        return


class SmtpFacts(FactsBase):
    def populate(self):
        cfg = self.get_config('system/smtp')
        self.facts.update({
            'smtp_server': cfg['smtpServer'],
            'smtp_username': cfg['smtpUser'],
            'smtp_password': cfg['smtpPassword'],
        })


class GreTunnelFacts(FactsBase):
    def populate(self):
        def create_tunnel(tun_cfg):
            return {
                'remote_ips': tun_cfg['greRemoteIps'],
                'interface': tun_cfg['interface'],
                'local_ip': tun_cfg['localIp'],
                'subnet_length': tun_cfg['subnetBitLength'],
            }

        cfg = self.get_config('gre-tunnels')
        self.facts['gre_tunnels'] = [
            create_tunnel(t) for t in cfg.get('gre-tunnels', [])]


class License(FactsBase):
    def populate(self):
        cfg_list = []
        server_cfg = self.get_config('license/server/')
        cfg_list.append({'server_id': server_cfg['serverId']})
        capabilities_cfg = self.get_config('license/capabilities/')
        for capability in capabilities_cfg['capabilities']:
            cap = {
                'capability': capability['capability'],
                'expiration': capability['expiration'],
                'requested': capability['requested'],
                'granted': capability['granted']
            }
            cfg_list.append(cap)
        self.facts.update({'aed_license': cfg_list})


class GeneralSettingsFacts(FactsBase):
    def populate(self):
        cfg = self.get_config('general-settings')
        self.facts['url_hostname'] = cfg['urlHostName']


class Interfaces(FactsBase):
    """Facts for interfaces"""

    def populate(self):
        """Gather relevant data for interfaces and format it
        for display
        """
        lp_param_map = [
            ('link_propagation_up_timeout', 'linkPropagationUpTimeout', int),
            ('link_propagation_down_timeout', 'linkPropagationDownTimeout', int)]
        intf_param_map = [
            ('name', 'interfaceName', str),
            ('addr', 'address', str)]

        intf_config = self.get_config('mitigation-interfaces')

        intf_config_list = []
        intf_config_list.append(rest_to_ans(intf_config, lp_param_map))

        for intf in intf_config.get('mitigationInterfaces'):
            intf_config_list.append(rest_to_ans(intf, intf_param_map))

        self.facts.update({'aed_interfaces': intf_config_list})

        return


FACT_SUBSETS = dict(
    device_info=DeviceInfo,
    operational_status=OperationalStatus,
    protection_groups=ProtectionGroups,
    server_types=ServerTypes,
    smtp=SmtpFacts,
    gre_tunnels=GreTunnelFacts,
    license=License,
    general_settings=GeneralSettingsFacts,
    interfaces=Interfaces
)
VALID_SUBSETS = frozenset(FACT_SUBSETS.keys())


def main():
    """ main entry point for module execution
    """
    argument_spec = dict(
        gather_subset=dict(default=["all"], type=list)
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False
    )

    warnings = list()
    check_args(module, warnings)

    gather_subset = module.params['gather_subset']
    runable_subsets = set()
    exclude_subsets = set()
    with exception_context(module, Exception):
        for subset in gather_subset:
            if subset == 'all':
                runable_subsets.update(VALID_SUBSETS)
                continue

            if subset.startswith('!'):
                subset = subset[1:]
                if subset == 'all':
                    exclude_subsets.update(VALID_SUBSETS)
                    continue
                exclude = True
            else:
                exclude = False

            if subset not in VALID_SUBSETS:
                module.fail_json(msg='Bad subset')

            if exclude:
                exclude_subsets.add(subset)
            else:
                runable_subsets.add(subset)

        if not runable_subsets:
            runable_subsets.update(VALID_SUBSETS)

        runable_subsets.difference_update(exclude_subsets)
        # runable_subsets.add('default') # API isn't available yet
        facts = dict()
        facts['gather_subset'] = list(runable_subsets)

        instances = list()
        for key in runable_subsets:
            instances.append(FACT_SUBSETS[key](module))

        for inst in instances:
            inst.populate()
            facts.update(inst.facts)
            warnings.extend(inst.warnings)

    ansible_facts = dict()
    for key, value in iteritems(facts):
        key = 'ansible_net_%s' % key
        ansible_facts[key] = value

    module.exit_json(ansible_facts=ansible_facts, warnings=warnings)


if __name__ == '__main__':
    main()

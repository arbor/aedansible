#!/usr/bin/python

# Copyright: (c) 2019, NETSCOUT
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: aed_server_type
version_added: "2.7"
author: "Chris Hartmann, <ansible-aed@netscout.com>"
short_description: Manage AED protection groups
description:
  - Module to manage AED server types and relevant configurations.
notes:
  - Supports check mode.
options:
    name:
        description:
            - Name of the server type.
        required: true
        type: str
    present:
        description:
            - Indicate if server type should exist.
        type: bool
    base_server_type:
        description:
            - The base server type to use when creating a new server type.
              Required when creating new server type.
        required: true
        type: str
    stix_enabled:
        description:
            - Filters traffic based on the indicators in STIX feeds. If you
              disable this category, protection groups that use this server
              type do not filter traffic based on the STIX indicators.
        type: bool
    http_reporting:
        description:
            - Set HTTP Reporting for this server type. If disabled, protection
              groups of this server type will not display Top URLs and Top
              Domains. This setting affects all Protection Levels.
        type: bool
    protection_level_high:
        description:
            - High protection level settings for the server type.
        suboptions:
            appbehavior_interrupt_count:
                description:
                    - Blocks traffic from sources that repeatedly interrupt HTTP
                      requests, and places those sources on the temporary blocked
                      sources list.
                type: int
            botnet_basic:
                description:
                    - Blocks traffic that matches the signatures used by bots.
                      This enables Basic Botnet Prevention
                type: bool
            botnet_segment:
                description:
                    - Blocks traffic that matches the signatures used by bots.
                      Prevent slow request attacks.
                type: bool
            botnet_signatures:
                description:
                    - Enable AIF Botnet Signatures.
                type: bool
            connection_limit_enabled:
                description:
                    - Limits the number of concurrent connections originating
                      from a single host.
                type: bool
            detect_icmp_enabled:
                desctiption:
                    - Detects sources sending ICMP traffic above the configured
                      thresholds, and places those sources on the temporary
                      blocked sources list.
                type: bool
            detect_icmp_bps:
                description:
                    - ICMP flood detection maximum bps.
                type: int
            detect_icmp_rate:
                description:
                    - ICMP flood deteciont maximum pps.
                type: int
            detect_syn_flood_enabled:
                description:
                    - Detects sources sending TCP SYN traffic above the
                      configured thresholds, and places those sources on the
                      temporary blocked sources list.
                type: bool
            detect_syn_flood_delta_rate:
                description:
                    - SYN flood SYN/ACK delta rate.
                type: int
            detect_syn_flood_rate:
                description:
                    - SYN flood SYN rate.
                type: int
            dns_auth_enable:
                description:
                    - Authenticates DNS requests and drops those that cannot
                      be authenticated within a specified time.
                type: bool
            dns_malform_enable:
                description:
                    - Drops the DNS requests on port 53 that do not conform to
                      RFC standards.
                type: bool
            dns_nx_domain_rate:
                description:
                    - Drops the traffic from any host that generates more
                      consecutive failed DNS requests than the configured limit,
                      and then blacklists the source host.
                type: int
            dns_query_rate:
                description:
                    - Drops the DNS request traffic that exceeds the configured
                      rate limit, and then blacklists the source host.
                type: int
            dns_regex_list:
                description:
                    - Blocks DNS requests which match a configured regular
                      expression.
                type: list
            filter_list:
                description:
                    - Uses configurable filters to drop or pass traffic. Create
                      drop rules to drop the traffic that matches the specified
                      FCAP expression. Create pass rules to pass the matching
                      traffic without involving further countermeasures.
                type: list
            fragmentation_detection_enabled:
                description:
                    - Blocks any traffic that exceeds the configured thresholds
                      for IP packet fragments. Temporarily blocks the source
                      host if the protection level is medium or high.
                type: bool
            fragmentation_detection_bps:
                description:
                    - Fragmentation detection maximum bps threshold.
                type: int
            fragmentation_detection_pps:
                description:
                    - Fragmentation detection maximum pps threshold.
                type: int
            http_malform_enabled:
                description:
                    - Drops the HTTP traffic that does not conform to RFC
                      standards for request headers, and then blacklists the
                      source hosts.
                type: bool
            http_proxy_detect_enabled:
                description:
                    - Prevents the global blocking of all the traffic from a CDN
                      or proxy when threatening traffic from that CDN or proxy
                      is detected.
                type: bool
            http_rate_limit_object_rate:
                description:
                    - Drops the HTTP request traffic that exceeds any of the
                      configured rate limits. Object rate defines the HTTP URL
                      limit.
                type: int
            http_rate_limit_request_rate:
                description:
                    - Drops the HTTP request traffic that exceeds any of the
                      configured rate limits. Object rate defines the HTTP
                      request limit.
                type: int
            http_regex_list:
                description:
                    - Blocks HTTP requests which match a configured regular
                      expression.
                type: list
            idle_reset_enabled:
                description:
                    - Blocks TCP connections that fail to make significant
                      progress thereby protecting the server against slow
                      request attacks. Sources that have multiple consecutive
                      connections blocked will be placed on the temporary
                      blocked sources list.
                type: bool
            idle_reset_bit_rate:
                description:
                    - Idle reset minimum request bit rate.
                type: int
            idle_reset_idle_timeout:
                description:
                    - TCP Connection idle timeout.
                type: int
            idle_reset_init_size:
                description:
                    - Initial timeout required data in bytes for idle reset.
                type: int
            idle_reset_init_timeout:
                description:
                    - TCP Connection initial timeout for idle reset.
                type: int
            idle_reset_num_idles:
                description:
                    - Consecutive violations before blocking source for idle
                      reset.
                type: int
            idle_reset_track_long_lived:
                description:
                    - Track connections after initial state for idle resets.
                type: bool
            multicast_enabled:
                description:
                    - Blocks any traffic whose source is a designated multicast
                      address.
                type: bool
            private_addresses_enabled:
                description:
                    - Blocks any traffic whose source is a designated private
                      address.
                type: bool
            rate_based_blocking_bps:
                description:
                    - Detects sources that exceed the configured thresholds,
                      and then places those sources on the temporary blocked
                      sources list that exceed this bps threshold.
                type: int
            rate_based_blocking_pps:
                description:
                    - Detects sources that exceed the configured thresholds,
                      and then places those sources on the temporary blocked
                      sources list that exceed this threshold.
                type: int
            regex_enabled:
                description:
                    - Matches packets to the configured TCP or UDP ports and a
                      regular expression, and then drops the packets, or places
                      those sources on the temporary blocked sources list.
                type: bool
            regex_blacklist_enable:
                description:
                    - Determine whether to drop or blacklist packet.  If set to
                      True, will blacklist offending hosts.  If set to False
                      will just drop packets that match regex.
                type: bool
            regex_include_headers:
                description:
                    - Apply regular expression to packet headers as well as
                      packet payload.
                type: bool
            regex_match_source_port:
                description:
                    - Determine whether to match source or destination ports.
                      Setting this to True will match source ports, setting to
                      False will match destination ports.
                type: bool
            regex_pattern:
                description:
                    - Payload regex pattern used to match packets.
                type: list
            regex_tcp_ports:
                description:
                    - Payload regular expression TCP ports to match.
                type: list
            regex_udp_ports:
                description:
                    - Payload regular expression UDP ports to match.
                type: list
            reputation_categories:
                description:
                    - Dictionary mapping ASERT threat categories to
                      {'confidence', 'enabled'} dicts.
                type: dict
            reputation_custom_confidence
                description:
                    - Custom default confidence index for ASERT threat
                      categoies.
                type: int
            reputation_enabled:
                description:
                    - Enable Atlas Intelligence Feed's threat categories.
                type: bool
            reputation_use_custom:
                description:
                    - Enable custom default confidence index for ASERT threat
                      categories.
                type: bool
            shaping_enabled:
                description:
                    - Analyzes the traffic that was not dropped by any of the
                      other countermeasures. Any traffic that matches the
                      specified FCAP expression and exceeds the configured rate
                      limits is dropped.
                type: bool
            shaping_bps:
                description:
                    - Maximum bps to apply to traffic shaping.
                type: int
            shaping_filter:
                description:
                    - Filter to match traffic that will be applied to traffic
                      shaping.
                type: list
            shaping_pps:
                description:
                    - Maximum pps to apply to traffic shaping.
                type: int

            sip_malform_enabled:
                description:
                    - Drops the SIP traffic that does not conform to RFC
                      standards, and then blacklists the source hosts.
                type: bool
            sip_request_rate:
                description:
                    - Drops the SIP request traffic that exceeds the configured
                      rate limit, and then blacklists the source host.
                type: int
            syn_auth_enabled:
                description:
                    - Initiates a three-way handshake with the hosts that
                      initiate TCP connections and drops the traffic from hosts
                      that do not respond properly.
                type: bool
            syn_auth_automation_enabled:
                description:
                    - Enable spoofed SYN flood prevention automation.
                type: bool
            syn_auth_automation_threshold:
                description:
                    - SYN flood prevention automation threshold pps.
                type: int

            syn_auth_destination_ports:
                description:
                    - list of ports to NOT apply SYN auth against. (EXCEPT on
                      these ports..)
                type: list

            syn_auth_http_auth_enabled:
                description:
                    - Add HTTP specific authentication options to SYN auth SYN
                      flood protection.
                type: bool
            syn_auth_http_auth_method:
                description:
                    - Set the HTTP authentication to use for spoofed SYN
                      protection when HTTP auth is enabled.
                choices: ['javascript', 'redirect', 'soft_reset']
                type: str
            syn_auth_out_of_seq_enabled:
                description:
                    - Enable TCP Out of Sequence Authentication
                type: bool
            tls_malform_enabled:
                description:
                    - Blocks TLS requests that are not valid or do not complete
                      a successful handshake in an appropriate amount of time.
                type: bool
            udp_flood_enabled:
                description:
                    - Blocks any traffic that exceeds the configured thresholds
                      for UDP packets. Temporarily blocks the source host if the
                      protection level is medium or high.
                type: bool
            udp_flood_bps:
                description:
                    - Maximum bps allowed before triggering UDP flood.
                type: int
            udp_flood_pps:
                description:
                    - Maximum pps allowed before triggering UDP flood.
                type: bool
            webcrawler_enabled:
                description:
                    - Enable web crawler support with the ATLAS intelligence
                      feed.
                type: bool
    protection_level_low:
        description:
            - Low protection level settings for the server type.
        suboptions:
                - Same suboptions as protection_level_high suboptions.
    protection_level_medium:
        description:
            - Medium protection level settings for the server type.
        suboptions:
                - Same suboptions as protection_level_high suboptions.
"""

EXAMPLES = """
- name: create custom DNS server type
  aed_server_type:
    name: "Custom DNS Server"
    present: true
    base_server_type: "DNS Server"
    stix_enabled: true
    protection_level_high:
      dns_auth_enable: true
      dns_malform_enable: true
      dns_nx_domain_rate: 100
      dns_query_rate: 1000
      dns_regex_list: [ '.*\.ru', '.*\.cn' ]
    protection_level_medium:
      dns_auth_enable: true
      dns_malform_enable: true
      dns_nx_domain_rate: 1000
      dns_query_rate: 10000
      dns_regex_list: [ '.*\.ru', '.*\.cn' ]
    protection_level_low:
      dns_auth_enable: false
      dns_malform_enable: false
      dns_nx_domain_rate: 5000
      dns_query_rate: 50000
      dns_regex_list: [ '.*\.ru', '.*\.cn' ]
"""

RETURN = """
deployment_state:
    description: Returns the current settings for the given server type.
    returned: always
    type: dict
    sample: {
        "http_reporting": true,
        "name": "ansible-test",
        "present": true,
        "profiling_duration": 0,
        "profiling_start": 0,
        "profilling": false,
        "protection_level_high": {
            "appbehavior_interrupt_count": 3,
            "botnet_basic": true,
            "botnet_segment": true,
            "botnet_signatures": true,
            "connection_limit_enabled": true,
            "detect_icmp_bps": 45000,
            "detect_icmp_enabled": true,
            "detect_icmp_rate": 100,
            "detect_syn_flood_delta_rate": 15,
            "detect_syn_flood_enabled": true,
            "detect_syn_flood_rate": 45,
            "dns_auth_enable": true,
            "dns_malform_enable": true,
            "dns_nx_domain_rate": 100,
            "dns_query_rate": 1000,
            "dns_regex_list": [
                '.*\.ru',
                '.*\.cn'
            ],
            "filter_list": [],
            "fragmentation_detection_bps": 400000,
            "fragmentation_detection_enabled": true,
            "fragmentation_detection_pps": 60,
            "http_malform_enabled": true,
            "http_proxy_detect_enabled": false,
            "http_rate_limit_object_rate": 10,
            "http_rate_limit_request_rate": 100,
            "http_regex_list": [],
            "idle_reset_bit_rate": 1000,
            "idle_reset_enabled": true,
            "idle_reset_idle_timeout": 120,
            "idle_reset_init_size": 50,
            "idle_reset_init_timeout": 15,
            "idle_reset_num_idles": 3,
            "idle_reset_track_long_lived": true,
            "multicast_enabled": false,
            "private_addresses_enabled": false,
            "rate_based_blocking_bps": 0,
            "rate_based_blocking_pps": 5000,
            "regex_blacklist_enable": false,
            "regex_enabled": false,
            "regex_include_headers": false,
            "regex_match_source_port": false,
            "regex_pattern": [],
            "regex_tcp_ports": [],
            "regex_udp_ports": [],
            "reputation_asert_confidence": null,
            "reputation_categories": {},
            "reputation_custom_confidence": null,
            "reputation_enabled": false,
            "reputation_use_custom": false,
            "shaping_bps": 0,
            "shaping_enabled": false,
            "shaping_filter": [
                "proto icmp"
            ],
            "shaping_pps": 1000,
            "sip_malform_enabled": false,
            "sip_request_rate": 0,
            "syn_auth_automation_enabled": false,
            "syn_auth_automation_threshold": 2500,
            "syn_auth_destination_ports": [
                25
            ],
            "syn_auth_enabled": true,
            "syn_auth_http_auth_enabled": false,
            "syn_auth_http_auth_method": "redirect",
            "tls_malform_enabled": true,
            "udp_flood_bps": 0,
            "udp_flood_enabled": false,
            "udp_flood_pps": 0,
            "webcrawler_enabled": true
        },
        "protection_level_low": {
            "appbehavior_interrupt_count": 10,
            "botnet_basic": true,
            "botnet_segment": true,
            "botnet_signatures": true,
            "connection_limit_enabled": false,
            "detect_icmp_bps": 45000,
            "detect_icmp_enabled": false,
            "detect_icmp_rate": 100,
            "detect_syn_flood_delta_rate": 50,
            "detect_syn_flood_enabled": true,
            "detect_syn_flood_rate": 150,
            "dns_auth_enable": false,
            "dns_malform_enable": false,
            "dns_nx_domain_rate": 5000,
            "dns_query_rate": 50000,
            "dns_regex_list": [
                '.*\.ru',
                '.*\.cn'
            ],
            "filter_list": [],
            "fragmentation_detection_bps": 400000,
            "fragmentation_detection_enabled": false,
            "fragmentation_detection_pps": 60,
            "http_malform_enabled": true,
            "http_proxy_detect_enabled": false,
            "http_rate_limit_object_rate": 0,
            "http_rate_limit_request_rate": 0,
            "http_regex_list": [],
            "idle_reset_bit_rate": 0,
            "idle_reset_enabled": true,
            "idle_reset_idle_timeout": 0,
            "idle_reset_init_size": 1,
            "idle_reset_init_timeout": 50,
            "idle_reset_num_idles": 5,
            "idle_reset_track_long_lived": false,
            "multicast_enabled": false,
            "private_addresses_enabled": false,
            "rate_based_blocking_bps": 0,
            "rate_based_blocking_pps": 0,
            "regex_blacklist_enable": false,
            "regex_enabled": false,
            "regex_include_headers": false,
            "regex_match_source_port": false,
            "regex_pattern": [],
            "regex_tcp_ports": [],
            "regex_udp_ports": [],
            "reputation_asert_confidence": null,
            "reputation_categories": {},
            "reputation_custom_confidence": null,
            "reputation_enabled": false,
            "reputation_use_custom": false,
            "shaping_bps": 0,
            "shaping_enabled": false,
            "shaping_filter": [
                "proto icmp"
            ],
            "shaping_pps": 2000,
            "sip_malform_enabled": false,
            "sip_request_rate": 0,
            "syn_auth_automation_enabled": false,
            "syn_auth_automation_threshold": 2500,
            "syn_auth_destination_ports": [
                25
            ],
            "syn_auth_enabled": false,
            "syn_auth_http_auth_enabled": false,
            "syn_auth_http_auth_method": "redirect",
            "tls_malform_enabled": false,
            "udp_flood_bps": 0,
            "udp_flood_enabled": false,
            "udp_flood_pps": 0,
            "webcrawler_enabled": true
        },
        "protection_level_medium": {
            "appbehavior_interrupt_count": 5,
            "botnet_basic": true,
            "botnet_segment": true,
            "botnet_signatures": true,
            "connection_limit_enabled": true,
            "detect_icmp_bps": 45000,
            "detect_icmp_enabled": true,
            "detect_icmp_rate": 100,
            "detect_syn_flood_delta_rate": 30,
            "detect_syn_flood_enabled": true,
            "detect_syn_flood_rate": 90,
            "dns_auth_enable": true,
            "dns_malform_enable": true,
            "dns_nx_domain_rate": 1000,
            "dns_query_rate": 10000,
            "dns_regex_list": [
                '.*\.ru',
                '.*\.cn'
            ],
            "filter_list": [],
            "fragmentation_detection_bps": 400000,
            "fragmentation_detection_enabled": true,
            "fragmentation_detection_pps": 60,
            "http_malform_enabled": true,
            "http_proxy_detect_enabled": false,
            "http_rate_limit_object_rate": 15,
            "http_rate_limit_request_rate": 500,
            "http_regex_list": [],
            "idle_reset_bit_rate": 200,
            "idle_reset_enabled": true,
            "idle_reset_idle_timeout": 120,
            "idle_reset_init_size": 20,
            "idle_reset_init_timeout": 25,
            "idle_reset_num_idles": 3,
            "idle_reset_track_long_lived": true,
            "multicast_enabled": false,
            "private_addresses_enabled": false,
            "rate_based_blocking_bps": 0,
            "rate_based_blocking_pps": 10000,
            "regex_blacklist_enable": false,
            "regex_enabled": false,
            "regex_include_headers": false,
            "regex_match_source_port": false,
            "regex_pattern": [],
            "regex_tcp_ports": [],
            "regex_udp_ports": [],
            "reputation_asert_confidence": null,
            "reputation_categories": {},
            "reputation_custom_confidence": null,
            "reputation_enabled": false,
            "reputation_use_custom": false,
            "shaping_bps": 0,
            "shaping_enabled": false,
            "shaping_filter": [
                "proto icmp"
            ],
            "shaping_pps": 1500,
            "sip_malform_enabled": false,
            "sip_request_rate": 0,
            "syn_auth_automation_enabled": false,
            "syn_auth_automation_threshold": 2500,
            "syn_auth_destination_ports": [
                25
            ],
            "syn_auth_enabled": false,
            "syn_auth_http_auth_enabled": false,
            "syn_auth_http_auth_method": "redirect",
            "tls_malform_enabled": true,
            "udp_flood_bps": 0,
            "udp_flood_enabled": false,
            "udp_flood_pps": 0,
            "webcrawler_enabled": true
        },
        "server_type": 32,
        "stix_enabled": true
    }
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
                                                  ResponseCodes,
                                                  exception_context)

PARAM_MAP = [
    ('name', 'serverName', str),
    ('server_type', 'serverType', int),
    ('http_reporting', 'httpReporting', bool),
    ('profilling', 'profiling', bool),
    ('profiling_duration', 'profilingDuration', int),
    ('profiling_start', 'profilingStart', int),
    ('stix_enabled', 'stixEnabled', None),
]

P_LEVELS = [
    'protection_level_high',
    'protection_level_low',
    'protection_level_medium'
]

P_LEVEL_MAP = [
    ('appbehavior',
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
         ('detect_syn_flood_delta_rate', 'synAckDeltaRate', int),
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
         ('idle_reset_track_long_lived', 'trackLongLived', bool)]),
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
         ('reputation_categories', 'categories', dict),
         ('reputation_custom_confidence', 'customConfidence', int),
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
         ('syn_auth_automation_enabled', 'automationEnabled', bool),
         ('syn_auth_automation_threshold', 'automationThreshold', int),
         ('syn_auth_destination_ports', 'dstPorts', list),
         ('syn_auth_out_of_seq_enabled', 'outOfSeqEnabled', bool),
         ('syn_auth_http_auth_enabled', 'httpAuthEnabled', bool),
         ('syn_auth_http_auth_method', 'javascriptEnabled', None),
         ('syn_auth_http_auth_method', 'softResetEnabled', None)]),
    ('tlsMalform',
        [('tls_malform_enabled', 'enabled', bool)]),
    ('udpFlood',
        [('udp_flood_enabled', 'enabled', bool),
         ('udp_flood_bps', 'bps', int),
         ('udp_flood_pps', 'pps', int)]),
    ('webcrawler',
        [('webcrawler_enabled', 'enabled', bool)]),
    ('zombie',
        [('rate_based_blocking_bps', 'bps', int),
         ('rate_based_blocking_pps', 'pps', int)])
]


def method_to_attrs(method):
    method_map = {
        'redirect': {
            'javascriptEnabled': False,
            'softResetEnabled': False,
        },
        'soft_reset': {
            'javascriptEnabled': False,
            'softResetEnabled': True,
        },
        'javascript': {
            'javascriptEnabled': True,
            'softResetEnabled': False,
        }
    }
    return method_map[method]


def attrs_to_method(settings):
    if not settings.get('javascriptEnabled') and settings.get('softResetEnabled'):
        return 'soft_reset'
    elif settings.get('javascriptEnabled') and not settings.get('softResetEnabled'):
        return 'javascript'
    else:
        return 'redirect'


def pl_rest_to_ans(rest_dict, param_map):
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

        # Fix up syn_auth_http_auth_method key
        if setting == 'synAuth' and setting_dict.get('httpAuthEnabled'):
            ans_dict['syn_auth_http_auth_method'] = attrs_to_method(setting_dict)

    return ans_dict


def pl_ans_to_rest(ans_dict, param_map):
    rest_dict = dict()

    for setting, setting_param_map in param_map:
        for ans_key, rest_key, func in setting_param_map:
            val = ans_dict.get(ans_key, None)
            if ans_key == 'syn_auth_http_auth_method' and val is not None:
                rest_dict.setdefault(setting, {})
                rest_dict[setting].update(method_to_attrs(val))

            elif val is not None:
                if func:
                    val = func(val)
                rest_dict.setdefault(setting, {})
                rest_dict[setting][rest_key] = val

    return rest_dict


def get_have(api, module):
    st_name = module.params.get('name')

    resp_code, raw_config = api.get_config(
        'protection-groups/server-types/',
        query_params=dict(serverName=st_name)
    )

    if resp_code in ResponseCodes.GOOD_RESP:
        st_list = raw_config.get('server-types')
        if st_list is None:
            # Need to create it, requires a 'base' server type.
            if not (
                module.params.get('base_server_type')
            ):
                raise AEDAPIError(
                    'Server Type "{}" does not exist, creating new server type '
                    'requires base_server_type defined'.format(
                        st_name)
                )
            return dict(
                name=st_name,
                present=False,
            )

        elif len(st_list) is 1:
            rest_dict = st_list[0]

            ans_dict = rest_to_ans(
                rest_dict, PARAM_MAP
            )

            ans_dict['protection_level_high'] = pl_rest_to_ans(
                rest_dict['protectionLevels']['high'], P_LEVEL_MAP
            )
            ans_dict['protection_level_low'] = pl_rest_to_ans(
                rest_dict['protectionLevels']['low'], P_LEVEL_MAP
            )
            ans_dict['protection_level_medium'] = pl_rest_to_ans(
                rest_dict['protectionLevels']['medium'], P_LEVEL_MAP
            )

            ans_dict['present'] = True

            return ans_dict

        else:  # not good....
            raise AEDAPIError(
                'Multiple Server Types match name, can only configure '
                'one at a time.'
            )
    else:
        raise AEDAPIError(
            'APIError: Failed fetching config. '
            'response code:{}, response:{}'.format(
                resp_code, raw_config)
        )


def get_want(module):
    wanted = {
        k: v for k, v in module.params.items() if v is not None
    }
    wanted.pop('base_server_type', None)  # Only used for new ST
    for p_level in P_LEVELS:
        p_level_settings = module.params.get(p_level)
        if p_level_settings is None:
            continue
        wanted[p_level] = {
            k: v for k, v in p_level_settings.items() if v is not None
        }

    return wanted


def get_changes(have, want):
    changes = dict()
    if want['present'] and not have['present']:  # Make new
        changes.update(want)
    else:
        for key in want:
            if key in P_LEVELS:
                for p_level_key in want[key]:
                    if want[key][p_level_key] != have[key][p_level_key]:
                        # These couple of params are not returned as a list
                        # but as a single concatenated string. So `want`
                        # and `have` are always different. Convert `want`
                        # params to a single string and then compare.
                        if p_level_key in ['regex_pattern', 'shaping_filter']:
                            concat = ['\n'.join(want[key][p_level_key])]
                            if have[key][p_level_key] == concat:
                                continue
                        changes.setdefault(key, {})
                        changes[key][p_level_key] = want[key][p_level_key]
            elif want[key] != have[key]:
                changes[key] = want[key]

    return changes


def main():
    p_level_arg_spec = dict(
        appbehavior_interrupt_count=dict(type='int'),
        botnet_basic=dict(type='bool'),
        botnet_segment=dict(type='bool'),
        botnet_signatures=dict(type='bool'),
        connection_limit_enabled=dict(type='bool'),
        detect_icmp_enabled=dict(type='bool'),
        detect_icmp_bps=dict(type='int'),
        detect_icmp_rate=dict(type='int'),
        detect_syn_flood_enabled=dict(type='bool'),
        detect_syn_flood_delta_rate=dict(type='int'),
        detect_syn_flood_rate=dict(type='int'),
        dns_auth_enable=dict(type='bool'),
        dns_malform_enable=dict(type='bool'),
        dns_nx_domain_rate=dict(type='int'),
        dns_query_rate=dict(type='int'),
        dns_regex_list=dict(type='list'),
        filter_list=dict(type='list'),
        fragmentation_detection_enabled=dict(type='bool'),
        fragmentation_detection_bps=dict(type='int'),
        fragmentation_detection_pps=dict(type='int'),
        http_malform_enabled=dict(type='bool'),
        http_proxy_detect_enabled=dict(type='bool'),
        http_rate_limit_object_rate=dict(type='int'),
        http_rate_limit_request_rate=dict(type='int'),
        http_regex_list=dict(type='list'),
        idle_reset_enabled=dict(type='bool'),
        idle_reset_bit_rate=dict(type='int'),
        idle_reset_idle_timeout=dict(type='int'),
        idle_reset_init_size=dict(type='int'),
        idle_reset_init_timeout=dict(type='int'),
        idle_reset_num_idles=dict(type='int'),
        idle_reset_track_long_lived=dict(type='bool'),
        multicast_enabled=dict(type='bool'),
        private_addresses_enabled=dict(type='bool'),
        rate_based_blocking_bps=dict(type='int'),
        rate_based_blocking_pps=dict(type='int'),
        regex_enabled=dict(type='bool'),
        regex_blacklist_enable=dict(type='bool'),
        regex_include_headers=dict(type='bool'),
        regex_match_source_port=dict(type='bool'),
        regex_pattern=dict(type='list'),
        regex_tcp_ports=dict(type='list'),
        regex_udp_ports=dict(type='list'),
        reputation_enabled=dict(type='bool'),
        reputation_categories=dict(type='dict'),
        reputation_custom_confidence=dict(type='int'),
        reputation_use_custom=dict(type='bool'),
        shaping_enabled=dict(type='bool'),
        shaping_bps=dict(type='int'),
        shaping_filter=dict(type='list'),
        shaping_pps=dict(type='int'),
        sip_malform_enabled=dict(type='bool'),
        sip_request_rate=dict(type='int'),
        syn_auth_enabled=dict(type='bool'),
        syn_auth_automation_enabled=dict(type='bool'),
        syn_auth_automation_threshold=dict(type='int'),
        syn_auth_destination_ports=dict(type='list'),
        syn_auth_http_auth_enabled=dict(type='bool'),
        syn_auth_out_of_seq_enabled=dict(type='bool'),
        syn_auth_http_auth_method=dict(
            choices=['javascript', 'redirect', 'soft_reset']
        ),
        tls_malform_enabled=dict(type='bool'),
        udp_flood_enabled=dict(type='bool'),
        udp_flood_bps=dict(type='int'),
        udp_flood_pps=dict(type='int'),
        webcrawler_enabled=dict(type='bool'),
    )

    argument_spec = dict(
        name=dict(type='str', required=True),
        present=dict(type='bool', default=True),
        base_server_type=dict(type='str', required=True),
        stix_enabled=dict(type='bool'),
        http_reporting=dict(type='bool'),
        protection_level_high=dict(type='dict', options=p_level_arg_spec),
        protection_level_low=dict(type='dict', options=p_level_arg_spec),
        protection_level_medium=dict(type='dict', options=p_level_arg_spec)
    )

    # TODO Is this necc'y? At this point no aed_argument_spce
    argument_spec.update(aed_argument_spec)

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    with exception_context(module, Exception):
        connection = Connection(module._socket_path)

        api = AEDAPIBase(connection)
        warnings = list()
        check_args(module, warnings)

        # Get what you want and have...
        have = get_have(api, module)
        want = get_want(module)

        result = {'changed': False}

        if not want['present']:
            if not have['present']:  # Does not exist yet, will not exist.
                result['no_create'] = (
                    "{} does not exist and 'present' set to False.  Will not "
                    "bother creating to just remove it.".format(
                        want['name']))

            else:  # Must be present, so delete it
                result['delete name'] = '{}'.format(have['name'])
                result['changed'] = True

                if not module.check_mode:
                    server_type_id = have['server_type']
                    resp_code, new_config = api.delete_config(
                        command='protection-groups/server-types/{}/'.format(
                            server_type_id))
                    if resp_code not in ResponseCodes.GOOD_DEL_RESP:
                        raise AEDAPIError(
                            'APIError:did not delete {}. '
                            'response code:{}, response:{}'.format(
                                have['name'], resp_code, new_config))

            module.exit_json(**result)

        changes = get_changes(have, want)

        if changes:
            if module._diff:
                result['diff'] = {'prepared': json.dumps(changes)}
            result['changed'] = True

            # Create new ST if req'd
            if not have['present']:  # Need to create from parent_type
                base_st_name = module.params.get('base_server_type')
                resp_code, raw_config = api.get_config(
                    'protection-groups/server-types/',
                    query_params=dict(serverName=base_st_name))
                if resp_code in ResponseCodes.GOOD_RESP:
                    st_list = raw_config.get('server-types')
                    if st_list is None:
                        raise AEDAPIError(
                            'server-type "{}" does not exist, cannot '
                            'create new server-type from it.'.format(
                                base_st_name))
                else:
                    raise AEDAPIError(
                        'Failed attempting to lookup server-type {}.'.format(
                            base_st_name))
                base_new_st_on = st_list[0]['serverType']
                new_st_params = dict(
                    serverName=want['name'],
                    parentType=base_new_st_on)
                if not module.check_mode:
                    resp_code, new_config = api.create_config(
                        command='protection-groups/server-types/',
                        body_params=new_st_params)
                    if resp_code not in ResponseCodes.GOOD_RESP:
                        raise AEDAPIError(
                            'APIError:response while creating new '
                            'server-type. code:{}, response:{}'
                            .format(resp_code, new_config))
                # Need to rest_to_ans the new ST like a new object...
                have = get_have(api, module)
                changes = get_changes(have, want)

            parsed_changes = ans_to_rest(changes, PARAM_MAP)

            if changes.get('protection_level_high'):
                parsed_changes['protectionLevels'] = {}
                parsed_changes['protectionLevels']['high'] = (
                    pl_ans_to_rest(
                        changes['protection_level_high'], P_LEVEL_MAP))

            if changes.get('protection_level_low'):
                parsed_changes.setdefault('protectionLevels', {})
                parsed_changes['protectionLevels']['low'] = (
                    pl_ans_to_rest(
                        changes['protection_level_low'], P_LEVEL_MAP))

            if changes.get('protection_level_medium'):
                parsed_changes.setdefault('protectionLevels', {})
                parsed_changes['protectionLevels']['medium'] = (
                    pl_ans_to_rest(
                        changes['protection_level_medium'], P_LEVEL_MAP))

            if parsed_changes:
                if not module.check_mode:
                    server_type_id = have['server_type']
                    resp_code, new_config = api.push_config(
                        command='protection-groups/server-types/{}/'.format(
                            server_type_id),
                        body_params=parsed_changes)
                    if resp_code not in ResponseCodes.GOOD_RESP:
                        raise AEDAPIError(
                            'APIError: Failed patching config. '
                            'response code:{}, response:{}'.format(
                                resp_code, new_config))

        result['server_types_state'] = get_have(api, module)

    module.exit_json(**result)


if __name__ == '__main__':
    main()

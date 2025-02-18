'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-remoted' program is the server side daemon that communicates with the agents.
       Specifically, this test will check if 'wazuh-remoted' starts correclty when a valid
       'rids_closing_time' value is set.

tier: 0

modules:
    - remoted

components:
    - manager

daemons:
    - wazuh-remoted

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6

references:
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-remoted.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/remote.html
    - https://documentation.wazuh.com/current/user-manual/agents/agent-life-cycle.html
    - https://documentation.wazuh.com/current/user-manual/capabilities/agent-key-polling.html

tags:
    - remoted
'''
import os
import pytest

from wazuh_testing.api import compare_config_api_response
from wazuh_testing.tools.configuration import load_wazuh_configurations
from urllib3.exceptions import InsecureRequestWarning
import requests

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

parameters = [
    {'CONNECTION': 'secure', 'PORT': '1514', 'RIDS_CLOSING_TIME': '1s'},
    {'CONNECTION': 'secure', 'PORT': '1514', 'RIDS_CLOSING_TIME': '30s'},
    {'CONNECTION': 'secure', 'PORT': '1514', 'RIDS_CLOSING_TIME': '1m'},
    {'CONNECTION': 'secure', 'PORT': '1514', 'RIDS_CLOSING_TIME': '30m'},
    {'CONNECTION': 'secure', 'PORT': '1514', 'RIDS_CLOSING_TIME': '1h'},
    {'CONNECTION': 'secure', 'PORT': '1514', 'RIDS_CLOSING_TIME': '30h'},
    {'CONNECTION': 'secure', 'PORT': '1514', 'RIDS_CLOSING_TIME': '1d'},
    {'CONNECTION': 'secure', 'PORT': '1514', 'RIDS_CLOSING_TIME': '30d'}
]

metadata = [
    {'connection': 'secure', 'port': '1514', 'rids_closing_time': '1s'},
    {'connection': 'secure', 'port': '1514', 'rids_closing_time': '30s'},
    {'connection': 'secure', 'port': '1514', 'rids_closing_time': '1m'},
    {'connection': 'secure', 'port': '1514', 'rids_closing_time': '30m'},
    {'connection': 'secure', 'port': '1514', 'rids_closing_time': '1h'},
    {'connection': 'secure', 'port': '1514', 'rids_closing_time': '30h'},
    {'connection': 'secure', 'port': '1514', 'rids_closing_time': '1d'},
    {'connection': 'secure', 'port': '1514', 'rids_closing_time': '30d'}
]

configurations = load_wazuh_configurations(configurations_path, "test_basic_configuration_rids_closing_time",
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['CONNECTION'], x['PORT'], x['RIDS_CLOSING_TIME']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_rids_closing_time_valid(get_configuration, configure_environment, restart_remoted):
    '''
    description: Check that 'rids_closing_time' can be set with no errors. For this purpose, 
                 it uses the configuration from test cases and check if the selected cfg matches with the API response.
    
    wazuh_min_version: 4.2.0
    
    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing. Restart Wazuh is needed for applying the configuration.
        - restart_remoted:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.
    
    assertions:
        - Verify that remoted starts correctly.
        - Verify that the API query matches correctly with the configuration that ossec.conf contains.
        - Verify that the selected configuration is the same as the API response.
    
    input_description: A configuration template (test_basic_configuration_rids_closing_time) is contained in an external
                       YAML file, (wazuh_basic_configuration.yaml). That template is combined with different test cases
                       defined in the module. Those include configuration settings for the 'wazuh-remoted' daemon and
                       agents info.
    
    expected_output:
        - r'Started <pid>: .* Listening on port .*'
        - r'API query '{protocol}://{host}:{port}/manager/configuration?section=remote' doesn't match the 
          introduced configuration on ossec.conf.'
    
    tags:
        - simulator
        - rids
    '''
    cfg = get_configuration['metadata']

    # Check that API query return the selected configuration
    compare_config_api_response([cfg], 'remote')

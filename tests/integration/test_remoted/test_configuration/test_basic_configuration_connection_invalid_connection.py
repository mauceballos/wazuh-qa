'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-remoted' program is the server side daemon that communicates with the agents.
       Specifically, this test will check that the expected error message is produced
       when invalid 'connection' values are used in the configuration.

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

from wazuh_testing.tools.monitoring import REMOTED_DETECTOR_PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools import WAZUH_CONF_RELATIVE
import wazuh_testing.generic_callbacks as gc

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

parameters = [
    {'PROTOCOL': 'TCP', 'CONNECTION': 'Testing', 'PORT': '1514'}
]
metadata = [
    {'protocol': 'TCP', 'connection': 'Testing', 'port': '1514'}
]

configurations = load_wazuh_configurations(configurations_path, "test_basic_configuration_connection",
                                           params=parameters, metadata=metadata)
configuration_ids = [f"{x['PROTOCOL']}_{x['CONNECTION']}_{x['PORT']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_invalid_connection(get_configuration, configure_environment, restart_remoted):
    '''
    description: Check if `wazuh-remoted` fails using invalid 'connection' values and shows the expected error message
                 to inform about it. For this purpose, the test will set a configuration from the module test cases and
                 check if is correct using a FileMonitor catching the errors.
    
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
        - Verify that the agent has no 'connection' invalid value.
        - Verify that remoted logs an error in ossec.log when it had to.
        - Verify that remoted logs a critical error in ossec.log when it had to.
    
    input_description: A configuration template (test_basic_configuration_connection) is contained in an external YAML
                       file, (wazuh_basic_configuration.yaml). That template is combined with different test cases
                       defined in the module. Those include configuration settings for the 'wazuh-remoted' daemon and
                       agents info.
    
    expected_output:
        - The expected error output has not been produced
        - r'.* Invalid value for element .*.'
        - r'.* Configuration error at .*'
    
    tags:
        - simulator
        - remoted
    '''
    cfg = get_configuration['metadata']
    real_configuration = cfg.copy()

    real_configuration['protocol'] = cfg['protocol'].split(',')

    log_callback = gc.callback_invalid_value('connection', cfg['connection'], prefix=REMOTED_DETECTOR_PREFIX)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    log_callback = gc.callback_error_in_configuration('ERROR', prefix=REMOTED_DETECTOR_PREFIX,
                                                      conf_path=WAZUH_CONF_RELATIVE)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

    log_callback = gc.callback_error_in_configuration('CRITICAL', prefix=REMOTED_DETECTOR_PREFIX,
                                                      conf_path=WAZUH_CONF_RELATIVE)
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

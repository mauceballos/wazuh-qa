# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

import wazuh_testing.remote as remote
from wazuh_testing.tools.configuration import load_wazuh_configurations

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

# Set invalid local_ip configuration
parameters = [
    {'LOCAL_IP': '9.9.9.9', 'IPV6': 'no'},
    {'LOCAL_IP': '1.1.1.1', 'IPV6': 'no'},
    {'LOCAL_IP': '::ffff:909:909', 'IPV6': 'yes'},
    {'LOCAL_IP': '::ffff:101:101', 'IPV6': 'yes'}
]
metadata = [
    {'local_ip': '9.9.9.9', 'ipv6': 'no'},
    {'local_ip': '1.1.1.1', 'ipv6': 'no'},
    {'local_ip': '::ffff:909:909', 'ipv6': 'yes'},
    {'local_ip': '::ffff:101:101', 'ipv6': 'yes'}
]

configurations = load_wazuh_configurations(configurations_path, "test_basic_configuration_local_ip", params=parameters,
                                           metadata=metadata)

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')

configuration_ids = [f"{x['LOCAL_IP']}" for x in parameters]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_local_ip_invalid(get_configuration, configure_environment, restart_remoted):
    """Test if `wazuh-remoted` fails when invalid `local_ip` values are configured.

    Raises:
        AssertionError: if `wazuh-remoted` does not show in `ossec.log` expected error messages.
    """
    log_callback = remote.callback_error_bind_port()
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message="The expected error output has not been produced")

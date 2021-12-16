# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import pytest
import wazuh_testing.api as api
import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools import LOG_FILE_PATH, get_service
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service

wazuh_component = get_service()

LOGCOLLECTOR_DAEMON = "wazuh-logcollector"

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.darwin, pytest.mark.sunos5, pytest.mark.tier(level=0)]

# Configuration
no_restart_windows_after_configuration_set = True
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_basic_configuration.yaml')
local_internal_options = {'logcollector.debug': '2'}

local_internal_options = {'logcollector.debug': '2'}

parameters = [
    {'SOCKET_NAME': 'custom_socket', 'SOCKET_PATH': '/var/log/messages', 'LOCATION': "/tmp/testing.log",
     'LOG_FORMAT': 'syslog', 'TARGET': 'custom_socket'},
    {'SOCKET_NAME': 'custom_socket', 'SOCKET_PATH': '/var/log/messages', 'LOCATION': "/tmp/testing.log",
     'LOG_FORMAT': 'json', 'TARGET': 'custom_socket'},
    {'SOCKET_NAME': 'custom_socket2', 'SOCKET_PATH': '/var/log/messages', 'LOCATION': "/tmp/testing.log",
     'LOG_FORMAT': 'json', 'TARGET': 'custom_socket'},
]
metadata = [
    {'socket_name': 'custom_socket', 'socket_path': '/var/log/messages', 'location': "/tmp/testing.log",
     'log_format': 'syslog', 'target': 'custom_socket', 'valid_value': True},
    {'socket_name': 'custom_socket', 'socket_path': '/var/log/messages', 'location': "/tmp/testing.log",
     'log_format': 'json', 'target': 'custom_socket', 'valid_value': True},
    {'socket_name': 'custom_socket2', 'socket_path': '/var/log/messages', 'location': "/tmp/testing.log",
     'log_format': 'json', 'target': 'custom_socket', 'valid_value': False},
]

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=parameters,
                                           metadata=metadata)
configuration_ids = [f"{x['log_format']}_{x['target']}_{x['socket_name']}_{x['location']}_{x['socket_path']}"
                     for x in metadata]


def check_configuration_target_valid(cfg):
    """Check if the Wazuh module runs correctly and that it uses the designated socket.

    Ensure logcollector is running with the specified configuration, analyzing the designated socket and,
    in the case of the Wazuh server, check if the API answer for localfile configuration block coincides
    the selected configuration.

    Args:
        cfg (dict): Dictionary with the localfile configuration.

    Raises:
        TimeoutError: If the socket target callback is not generated.
        AssertError: In the case of a server instance, the API response is different than the real configuration.
    """
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    log_callback = logcollector.callback_socket_target(cfg['location'], cfg['target'])
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_TARGET_SOCKET)

    if wazuh_component == 'wazuh-manager':
        real_configuration = dict((key, cfg[key]) for key in ('location', 'target', 'log_format'))
        api.wait_until_api_ready()
        api.compare_config_api_response([real_configuration], 'localfile')


def check_configuration_target_invalid(cfg):
    """Check if Wazuh fails because of an invalid target configuration value.

    Args:
        cfg (dict): Dictionary with the localfile configuration.

    Raises:
        TimeoutError: If the error callbacks are not generated.
    """
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    log_callback = logcollector.callback_socket_not_defined(cfg['location'], cfg['target'])
    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_TARGET_SOCKET_NOT_FOUND)


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
def test_configuration_target(get_configuration, configure_environment, configure_local_internal_options_module):
    """Check if Wazuh target field of logcollector works properly.

    Ensure Wazuh component fails in the case of invalid values and works properly in the case of valid target values.

    Raises:
        TimeoutError: If the expected callbacks are not generated.
    """
    cfg = get_configuration['metadata']

    control_service('stop', daemon=LOGCOLLECTOR_DAEMON)
    truncate_file(LOG_FILE_PATH)

    if cfg['valid_value']:
        control_service('start', daemon=LOGCOLLECTOR_DAEMON)
        check_configuration_target_valid(cfg)
    else:
        control_service('start', daemon=LOGCOLLECTOR_DAEMON)
        check_configuration_target_invalid(cfg)

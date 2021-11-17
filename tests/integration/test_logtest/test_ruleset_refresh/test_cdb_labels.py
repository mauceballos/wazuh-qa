# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

from wazuh_testing.tools import WAZUH_PATH
from yaml import safe_load
from shutil import copy
from json import loads

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_path = os.path.join(test_data_path, 'cdb_list.yaml')

with open(messages_path) as f:
    test_cases = safe_load(f)

# Variables
logtest_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'sockets', 'logtest'))
receiver_sockets_params = [(logtest_path, 'AF_UNIX', 'TCP')]
receiver_sockets = None


# Fixtures
@pytest.fixture(scope='function')
def configure_cdbs_list(get_configuration, request):
    """Configure a custom cdbs for testing.
    Restart Wazuh is not needed for applying the configuration is optional.
    """

    # cdb configuration for testing
    cdb_dir = os.path.join(WAZUH_PATH, get_configuration['cdb_dir'])
    if not os.path.exists(cdb_dir):
        os.makedirs(cdb_dir)

    file_cdb_test = os.path.join(test_data_path, get_configuration['cdb_file'])
    file_cdb_dst = os.path.join(cdb_dir, get_configuration['cdb_file'])

    copy(file_cdb_test, file_cdb_dst)

    # rule configuration for testing
    rule_dir = os.path.join(WAZUH_PATH, get_configuration['rule_dir'])
    if not os.path.exists(rule_dir):
        os.makedirs(rule_dir)

    file_rule_test = os.path.join(test_data_path, get_configuration['rule_file'])
    file_rule_dst = os.path.join(rule_dir, get_configuration['rule_file'])

    copy(file_rule_test, file_rule_dst)

    yield

    # restore previous configuration
    os.remove(file_cdb_dst)
    if len(os.listdir(cdb_dir)) == 0:
        os.rmdir(cdb_dir)
    os.remove(file_rule_dst)
    if len(os.listdir(rule_dir)) == 0:
        os.rmdir(rule_dir)


@pytest.fixture(scope='module', params=test_cases, ids=[test_case['name'] for test_case in test_cases])
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def test_cdb_list(restart_required_logtest_daemons, get_configuration,
                  configure_environment, configure_cdbs_list,
                  wait_for_logtest_startup, connect_to_sockets_function):
    """Check that every test case run on logtest generates the adequate output."""

    # send the logtest request
    receiver_sockets[0].send(get_configuration['input'], size=True)

    # receive logtest reply and parse it
    response = receiver_sockets[0].receive(size=True).rstrip(b'\x00').decode()
    result = loads(response)

    assert result['error'] == 0
    if 'test_exclude' in get_configuration:
        assert 'cdb' not in result['data']['output']
    else:
        assert result['data']['output']['rule']['id'] == get_configuration['rule_id']

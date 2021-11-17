'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: This module verifies the correct behavior of the enrollment daemon 'wazuh-authd' under different messages.

tier: 0

modules:
    - authd

components:
    - manager

daemons:
    - wazuh-authd
    - wazuh-db
    - wazuh-modulesd

os_platform:
    - linux

os_version:
    - Amazon Linux 1
    - Amazon Linux 2
    - Arch Linux
    - CentOS 6
    - CentOS 7
    - CentOS 8
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 6
    - Red Hat 7
    - Red Hat 8
    - Ubuntu Bionic
    - Ubuntu Trusty
    - Ubuntu Xenial

tags:
    - enrollment
'''
import os
import subprocess
import time

import pytest
from wazuh_testing.tools import CLIENT_KEYS_PATH, LOG_FILE_PATH, WAZUH_DB_SOCKET_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.file import read_yaml, truncate_file
from wazuh_testing.authd import DAEMON_NAME, insert_pre_existent_agents

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
message_tests = read_yaml(os.path.join(test_data_path, 'authd_key_hash.yaml'))
configurations_path = os.path.join(test_data_path, 'wazuh_authd_configuration.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=None, metadata=None)

# Variables
log_monitor_paths = []
receiver_sockets_params = [(("localhost", 1515), 'AF_INET', 'SSL_TLSv1_2'), (WAZUH_DB_SOCKET_PATH, 'AF_UNIX', 'TCP')]
monitored_sockets_params = [('wazuh-modulesd', None, True), ('wazuh-db', None, True), ('wazuh-authd', None, True)]
receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures
test_case_ids = [f"{test_case['name'].lower().replace(' ', '-')}" for test_case in message_tests]


# Tests

@pytest.fixture(scope="module", params=configurations)
def get_configuration(request, ids=['authd_key_hash_config']):
    """
    Get configurations from the module
    """
    yield request.param


@pytest.fixture(scope='function', params=message_tests, ids=test_case_ids)
def get_current_test_case(request):
    """
    Get current test case from the module
    """
    return request.param


@pytest.fixture(scope='function')
def set_up_groups(get_current_test_case, request):
    """
    Set pre-existent groups.
    """

    groups = get_current_test_case.get('groups', [])

    for group in groups:
        subprocess.call(['/var/ossec/bin/agent_groups', '-a', '-g', f'{group}', '-q'])

    yield

    for group in groups:
        subprocess.call(['/var/ossec/bin/agent_groups', '-r', '-g', f'{group}', '-q'])


def test_ossec_auth_messages_with_key_hash(configure_environment, configure_sockets_environment,
                                           connect_to_sockets_function, set_up_groups, insert_pre_existent_agents,
                                           restart_authd_function, wait_for_authd_startup_function,
                                           get_current_test_case, tear_down):
    '''
    description:
        Checks that every input message in authd port generates the adequate output.

    wazuh_min_version:
        4.2.0

    parameters:
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - configure_sockets_environment:
            type: fixture
            brief: Configure the socket listener to receive and send messages on the sockets.
        - connect_to_sockets_function:
            type: fixture
            brief: Bind to the configured sockets at function scope.
        - set_up_groups:
            type: fixture
            brief: Set pre-existent groups.
        - insert_pre_existent_agents:
            type: fixture
            brief: adds the required agents to the client.keys and global.db
        - restart_authd_function:
            type: fixture
            brief: stops the wazuh-authd daemon.
        - wait_for_authd_startup_function:
            type: fixture
            brief: Waits until Authd is accepting connections.
        - get_current_test_case:
            type: fixture
            brief: gets the current test case from the tests' list
        - tear_down:
            type: fixture
            brief: cleans the client.keys file

    assertions:
        - The received output must match with expected
        - The enrollment messages are parsed as expected
        - The agent keys are denied if the hash is the same than the manager's

    input_description:
        Different test cases are contained in an external YAML file (authd_key_hash.yaml) which includes
        the different possible registration requests and the expected responses.

    expected_output:
        - Registration request responses on Authd socket
    '''
    case = get_current_test_case['test_case']

    for index, stage in enumerate(case):
        # Reopen socket (socket is closed by manager after sending message with client key)
        receiver_sockets[0].open()
        expected = stage['output']
        message = stage['input']
        receiver_sockets[0].send(message, size=False)
        timeout = time.time() + 10
        response = ''
        while response == '':
            response = receiver_sockets[0].receive().decode()
            if time.time() > timeout:
                raise ConnectionResetError('Manager did not respond to sent message!')
        assert response[:len(expected)] == expected, \
            'Failed stage "{}". Response was: {} instead of: {}' \
            .format(index+1, response, expected)

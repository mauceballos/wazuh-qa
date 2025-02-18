'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-logcollector' daemon monitors configured files and commands for new log messages.
       Specifically, these tests will check if the logcollector redirects the events from a monitored
       log file specified in the 'location' tag to a custom socket defined in the 'socket' section and
       specified in the 'target' tag. Log data collection is the real-time process of making sense out
       of the records generated by servers or devices. This component can receive logs through text files
       or Windows event logs. It can also directly receive logs via remote syslog which is useful
       for firewalls and other such devices.

tier: 1

modules:
    - logcollector

components:
    - agent
    - manager

daemons:
    - wazuh-logcollector

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
    - https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html#location
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html#target

tags:
    - logcollector_location_cust_sockets
'''
from os import path, unlink
from sys import platform
if platform != 'win32':
    from socket import AF_UNIX

from socket import SHUT_RDWR, SOCK_STREAM, SOCK_DGRAM, socket
from tempfile import gettempdir

import pytest

from wazuh_testing import global_parameters
from wazuh_testing import logcollector as lg
from wazuh_testing.tools import LOG_FILE_PATH, file
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=1)]

# Configuration
DAEMON_NAME = "wazuh-logcollector"
test_data_path = path.join(path.dirname(path.realpath(__file__)), 'data')
configurations_path = path.join(test_data_path, 'wazuh_location_custom_sockets_conf.yaml')
temp_dir = gettempdir()
log_test_path = path.join(temp_dir, 'wazuh-testing', 'test.log')
test_socket = None

local_internal_options = {
    'logcollector.debug': 2,
    'logcollector.state_interval': 5,
    'logcollector.queue_size': 2048,
    'monitord.rotate_log': 0
}

# Batch sizes of events to add to the log file
batch_size = [5, 10, 50, 100, 500, 1000, 5000, 10000]

parameters = [
    {'LOG_FORMAT': 'syslog', 'LOCATION': log_test_path, 'SOCKET_NAME': 'custom_socket',
     'SOCKET_PATH': '/var/run/custom.sock', 'MODE': 'tcp'},
    {'LOG_FORMAT': 'syslog', 'LOCATION': log_test_path, 'SOCKET_NAME': 'custom_socket',
     'SOCKET_PATH': '/var/run/custom.sock', 'MODE': 'udp'}
]

metadata = [
    {'log_format': 'syslog', 'location': log_test_path, 'socket_name': 'custom_socket', 'mode': 'tcp',
     'socket_path': '/var/run/custom.sock', 'log_line': "Jan  1 00:00:00 localhost test[0]: log line"},
    {'log_format': 'syslog', 'location': log_test_path, 'socket_name': 'custom_socket', 'mode': 'udp',
     'socket_path': '/var/run/custom.sock', 'log_line': "Jan  1 00:00:00 localhost test[0]: log line"},
]

file_structure = [
    {
        'folder_path': path.join(temp_dir, 'wazuh-testing'),
        'filename': ['test.log'],
        'content': f"{metadata[0]['log_line']}",
        'size_kib': 10240
    }
]

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"target_{x['socket_name']}_mode_{x['mode']}" for x in metadata]


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def get_local_internal_options():
    """Get internal configuration."""
    return local_internal_options


@pytest.fixture(scope='function')
def restart_logcollector(get_configuration, request):
    """Reset log file and start a new monitor."""
    control_service('stop', daemon=DAEMON_NAME)
    file.truncate_file(LOG_FILE_PATH)
    file_monitor = FileMonitor(LOG_FILE_PATH)
    setattr(request.module, 'wazuh_log_monitor', file_monitor)
    control_service('start', daemon=DAEMON_NAME)


@pytest.fixture(scope="function")
def create_socket(get_configuration):
    """Create a UNIX named socket for testing."""
    config = get_configuration['metadata']
    global test_socket
    # Check if the socket exists and unlink it
    if path.exists(config['socket_path']):
        unlink(config['socket_path'])

    if config['mode'] == "tcp":
        test_socket = socket(AF_UNIX, SOCK_STREAM)
        test_socket.bind(config['socket_path'])
        test_socket.listen()
    else:
        test_socket = socket(AF_UNIX, SOCK_DGRAM)
        test_socket.bind(config['socket_path'])
    yield
    try:
        test_socket.shutdown(SHUT_RDWR)
        test_socket.close()
    except OSError:
        # The socket is already closed
        pass
    finally:
        if path.exists(config['socket_path']):
            unlink(config['socket_path'])


@pytest.fixture(scope="module")
def get_files_list():
    """Get file list to create from the module."""
    return file_structure


@pytest.mark.skip(reason="Unexpected false positive, further investigation is required")
@pytest.mark.parametrize("batch", batch_size, ids=[f"batch_{x}" for x in batch_size])
def test_location_custom_sockets(get_local_internal_options, configure_local_internal_options,
                                 get_configuration, configure_environment, create_file_structure_module,
                                 batch, create_socket, restart_monitord, restart_logcollector):    
    '''
    description: Check if the 'wazuh-logcollector' use custom sockets when the 'location' option is used.
                 For this purpose, the test will create a UNIX 'named socket' and add it to the configuration
                 through the 'socket' section and the 'target' tag of the 'localfile' section. After this,
                 the test will verify that logcollector is connected to that socket. Then, it will generate
                 event batches of increasing size, and they will be added to the testing log file. Finally,
                 the test will verify that events are not dropped by analyzing the 'wazuh-logcollector.state' file.

    wazuh_min_version: 4.2.0

    parameters:
        - get_local_internal_options:
            type: fixture
            brief: Get internal configuration.
        - configure_local_internal_options:
            type: fixture
            brief: Set internal configuration for testing.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - create_file_structure_module:
            type: fixture
            brief: Create the specified file tree structure.
        - batch:
            type: fixture
            brief: Event batches to be added to the testing log file.
        - create_socket:
            type: fixture
            brief: Create a UNIX named socket for testing.
        - restart_monitord:
            type: fixture
            brief: Reset the log file and start a new monitor.
        - restart_logcollector:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.

    assertions:
        - Verify that the logcollector monitors the log file specified in the 'location' tag.
        - Verify that the logcollector connects to the custom socket specified in the 'target tag'.
        - Verify that no events are dropped from the monitored log file when event batches are smaller
          than the value of 'logcollector.queue_size' and vice versa.

    input_description: A configuration template (test_location_custom_sockets) is contained in an external YAML
                       file (wazuh_location_custom_sockets_conf.yaml). That template is combined with different
                       test cases defined in the module. Those include configuration settings
                       for the 'wazuh-logcollector' daemon.

    expected_output:
        - r'Analyzing file.*'
        - r'Connected to socket .*'

    tags:
        - logs
    '''
    config = get_configuration['metadata']

    # Ensure that the log file is being analyzed
    callback_message = lg.callback_analyzing_file(file=config['location'])
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            error_message=lg.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                            callback=callback_message)

    # Add one event to force logcollector to connect to the socket
    with open(config['location'], 'a') as f:
        f.write(f"{config['log_line']}\n")

    # Ensure that the logcollector is connected to the socket
    callback_message = lg.callback_socket_connected(socket_name=config['socket_name'],
                                                    socket_path=config['socket_path'])
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            error_message=lg.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                            callback=callback_message)

    # This way we make sure to get the statistics right at the beginning of an interval
    stats = lg.get_data_sending_stats(log_path=config['location'],
                                      socket_name=config['socket_name'])
    next_stats = lg.get_next_stats(current_stats=stats,
                                   log_path=config['location'],
                                   socket_name=config['socket_name'],
                                   state_interval=local_internal_options['logcollector.state_interval'])
    interval_drops = int(next_stats[0]['interval_drops'])

    # Add batches of events to log file and check if drops
    with open(config['location'], 'a') as f:
        for _ in range(batch):
            f.write(f"{config['log_line']}\n")

    next_stats = lg.get_next_stats(current_stats=next_stats[0],
                                   log_path=config['location'],
                                   socket_name=config['socket_name'],
                                   state_interval=local_internal_options['logcollector.state_interval'])
    interval_drops += int(next_stats[0]['interval_drops'])

    # Obtain next statistics in case dropped events appear during the next interval
    next_stats = lg.get_next_stats(current_stats=next_stats[0],
                                   log_path=config['location'],
                                   socket_name=config['socket_name'],
                                   state_interval=local_internal_options['logcollector.state_interval'])
    global_drops = int(next_stats[0]['global_drops'])
    interval_drops += int(next_stats[0]['interval_drops'])

    # Event drops should not occur with batches smaller than the value of "logcollector.queue_size".
    if batch > local_internal_options['logcollector.queue_size']:
        with pytest.raises(AssertionError):
            assert global_drops == interval_drops == 0, f"Event drops have been detected in batch {batch}."
    else:
        assert global_drops == interval_drops == 0, f"Event drops have been detected in batch {batch}."


@pytest.mark.skip(reason="Unexpected false positive, further investigation is required")
@pytest.mark.parametrize("batch", batch_size, ids=[f"batch_{x}" for x in batch_size])
def test_location_custom_sockets_offline(get_local_internal_options, configure_local_internal_options,
                                         get_configuration, configure_environment, create_file_structure_module,
                                         batch, create_socket, restart_logcollector):
    '''
    description: Check if the 'wazuh-logcollector' drops events when they are sent to a custom socket
                 that is unavailable. For this purpose, the test will create a UNIX 'named socket' and
                 add it to the configuration through the 'socket' section and the 'target' tag of the
                 'localfile' section. After this, the test will verify that logcollector is connected
                 to that socket. Then, it will close the socket and generate event batches of increasing
                 size that will be added to the testing log file. Finally, the test will verify that
                 all events sent are dropped by analyzing the 'wazuh-logcollector.state' file.

    wazuh_min_version: 4.2.0

    parameters:
        - get_local_internal_options:
            type: fixture
            brief: Get internal configuration.
        - configure_local_internal_options:
            type: fixture
            brief: Set internal configuration for testing.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - create_file_structure_module:
            type: fixture
            brief: Create the specified file tree structure.
        - batch:
            type: fixture
            brief: Event batches to be added to the testing log file.
        - create_socket:
            type: fixture
            brief: Create a UNIX named socket for testing.
        - restart_logcollector:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.

    assertions:
        - Verify that the logcollector monitors the log file specified in the 'location' tag.
        - Verify that the logcollector connects to the custom socket specified in the 'target tag'.
        - Verify that the logcollector closes the custom socket specified in the 'target tag'.
        - Verify that all events from the monitored log file are dropped because the custom socket is closed.

    input_description: A configuration template (test_location_custom_sockets) is contained in an external YAML
                       file (wazuh_location_custom_sockets_conf.yaml). That template is combined with different
                       test cases defined in the module. Those include configuration settings
                       for the 'wazuh-logcollector' daemon.

    expected_output:
        - r'Analyzing file.*'
        - r'Connected to socket .*'
        - r'Unable to connect to socket .*'

    tags:
        - logs
    '''
    config = get_configuration['metadata']
    global test_socket

    # Ensure that the log file is being analyzed
    callback_message = lg.callback_analyzing_file(file=config['location'])
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            error_message=lg.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                            callback=callback_message)

    # Add one event to force logcollector to connect to the socket
    with open(config['location'], 'a') as f:
        f.write(f"{config['log_line']}\n")

    # Ensure that the logcollector is connected to the socket
    callback_message = lg.callback_socket_connected(socket_name=config['socket_name'],
                                                    socket_path=config['socket_path'])
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            error_message=lg.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                            callback=callback_message)

    # Close socket
    test_socket.shutdown(SHUT_RDWR)
    test_socket.close()

    # Add another event to verify that logcollector cannot connect to the already closed socket
    with open(config['location'], 'a') as f:
        f.write(f"{config['log_line']}\n")

    # Ensure that the socket is closed
    callback_message = lg.callback_socket_offline(socket_name=config['socket_name'],
                                                  socket_path=config['socket_path'])
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            error_message=lg.GENERIC_CALLBACK_ERROR_COMMAND_MONITORING,
                            callback=callback_message)

    # This way we make sure to get the statistics right at the beginning of an interval
    stats = lg.get_data_sending_stats(log_path=config['location'],
                                      socket_name=config['socket_name'])
    next_stats = lg.get_next_stats(current_stats=stats,
                                   log_path=config['location'],
                                   socket_name=config['socket_name'],
                                   state_interval=local_internal_options['logcollector.state_interval'])
    interval_drops = int(next_stats[0]['interval_drops'])

    # Add batches of events to log file and check if drops
    with open(config['location'], 'a') as f:
        for _ in range(batch):
            f.write(f"{config['log_line']}\n")

    next_stats = lg.get_next_stats(current_stats=next_stats[0],
                                   log_path=config['location'],
                                   socket_name=config['socket_name'],
                                   state_interval=local_internal_options['logcollector.state_interval'])
    interval_drops += int(next_stats[0]['interval_drops'])

    # Obtain next statistics in case dropped events appear during the next interval
    next_stats = lg.get_next_stats(current_stats=next_stats[0],
                                   log_path=config['location'],
                                   socket_name=config['socket_name'],
                                   state_interval=local_internal_options['logcollector.state_interval'])
    global_drops = int(next_stats[0]['global_drops'])
    interval_drops += int(next_stats[0]['interval_drops'])

    # The number of global events must be the same as
    # the batch size plus one (the event to verify the closure of the socket).
    assert global_drops == batch + 1, "The global drops reported do not match those caused by the test."
    assert interval_drops == batch, "The interval drops reported do not match those caused by the test."

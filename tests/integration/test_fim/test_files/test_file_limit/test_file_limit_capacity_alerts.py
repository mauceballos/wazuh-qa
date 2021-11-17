'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts
       when these files are modified. Specifically, these tests will check if the threshold
       set in the 'file_limit' tag generates FIM events when the number of monitored files
       approaches this value.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks
       configured files for changes to the checksums, permissions, and ownership.

tier: 1

modules:
    - fim

components:
    - agent
    - manager

daemons:
    - wazuh-syscheckd

os_platform:
    - linux
    - windows

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
    - Windows 10
    - Windows 8
    - Windows 7
    - Windows Server 2019
    - Windows Server 2016
    - Windows Server 2012
    - Windows Server 2003
    - Windows XP

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#file-limit
    - https://en.wikipedia.org/wiki/Inode

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_file_limit
'''
import os
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, callback_file_limit_capacity, generate_params, create_file, \
    check_time_travel, REGULAR, delete_file, callback_file_limit_back_to_normal, \
    callback_entries_path_count
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.tier(level=1)]

# Variables
test_directories = [os.path.join(PREFIX, 'testdir1')]

directory_str = ','.join(test_directories)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1 = test_directories[0]

# Configurations


file_limit_list = ['100']
conf_params = {'TEST_DIRECTORIES': testdir1, 'MODULE_NAME': __name__}

p, m = generate_params(extra_params=conf_params, modes=['scheduled'],
                       apply_to_all=({'FILE_LIMIT': file_limit_elem} for file_limit_elem in file_limit_list))

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests


@pytest.mark.parametrize('percentage,tags_to_apply', [
    (80, {'file_limit_conf'}),
    (90, {'file_limit_conf'}),
    (0, {'file_limit_conf'})
])
def test_file_limit_capacity_alert(percentage, tags_to_apply, get_configuration, configure_environment,
                                   restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon generates events for different capacity thresholds limits when
                 using the 'schedule' monitoring mode. For this purpose, the test will monitor a directory in which
                 several testing files will be created, corresponding to different percentages of the total file limit.
                 Then, it will check if FIM events are generated when the number of files created exceeds 80% of
                 the total and when the number is less than that percentage. Finally, the test will verify that
                 on the FIM event, inodes and monitored files number match.

    wazuh_min_version: 4.2.0

    parameters:
        - percentage:
            type: int
            brief: Percentage of testing files to be created.
        - tags_to_apply:
            type: set
            brief: Run test if matches with a configuration identifier, skip otherwise.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that FIM events are generated when the number of files to be monitored
          exceeds the established threshold and vice versa.
        - Verify that the FIM events contain the same number of inodes and files in the monitored directory.

    input_description: A test case (file_limit_conf) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, it is
                       combined with the testing directory to be monitored defined in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' event if the testing directory is not ignored)
        - r'.*Sending DB * full alert.'
        - r'.*Sending DB back to normal alert.'
        - r'.*Fim inode entries*, path count'
        - r'.*Fim entries' (on Windows systems)

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    NUM_FILES = percentage + 1

    if percentage == 0:
        NUM_FILES = 0

    if percentage >= 80:  # Percentages 80 and 90
        for i in range(NUM_FILES):
            create_file(REGULAR, testdir1, f'test{i}')
    else:  # Database back to normal
        for i in range(91):
            delete_file(testdir1, f'test{i}')

    check_time_travel(True, monitor=wazuh_log_monitor)

    if percentage >= 80:  # Percentages 80 and 90
        file_limit_capacity = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                      callback=callback_file_limit_capacity,
                                                      error_message='Did not receive expected '
                                                                    '"DEBUG: ...: Sending DB ...% full alert." event'
                                                      ).result()

        if file_limit_capacity:
            assert file_limit_capacity == str(percentage), 'Wrong capacity log for DB file_limit'
        else:
            raise AssertionError('Wrong capacity log for DB file_limit')
    else:  # Database back to normal
        event_found = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                              callback=callback_file_limit_back_to_normal,
                                              error_message='Did not receive expected '
                                                            '"DEBUG: ...: Sending DB back to normal alert." event'
                                              ).result()

        assert event_found, 'Event "Sending DB back to normal alert." not found'

    entries, path_count = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                                  callback=callback_entries_path_count,
                                                  error_message='Did not receive expected '
                                                                '"Fim inode entries: ..." event'
                                                  ).result()

    check_time_travel(True, monitor=wazuh_log_monitor)

    if sys.platform != 'win32':
        if entries and path_count:
            assert entries == str(NUM_FILES) and path_count == str(NUM_FILES), 'Wrong number of inodes and path count'
        else:
            raise AssertionError('Wrong number of inodes and path count')
    else:
        if entries:
            assert entries == str(NUM_FILES), 'Wrong number of entries count'
        else:
            raise AssertionError('Wrong number of entries count')

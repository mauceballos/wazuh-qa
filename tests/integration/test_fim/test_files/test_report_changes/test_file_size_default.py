'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if FIM limits the size of the file
       monitored to generate 'diff' information to the default value of the 'file_size' tag when
       the 'report_changes' option is enabled.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#file-size

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_report_changes
'''
import os

import pytest
from test_fim.test_files.test_report_changes.common import generate_string, translate_size, make_diff_file_path, \
    disable_rt_delay, restore_rt_delay
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, REGULAR, callback_file_size_limit_reached, generate_params, create_file, \
    check_time_travel, callback_detect_event, modify_file_content
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.tier(level=1)]

# Variables

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_directories = [os.path.join(PREFIX, 'testdir1')]
directory_str = ','.join(test_directories)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1 = test_directories[0]

# Configurations

conf_params, conf_metadata = generate_params(extra_params={'REPORT_CHANGES': {'report_changes': 'yes'},
                                                           'TEST_DIRECTORIES': directory_str,
                                                           'MODULE_NAME': __name__})

configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Functions

def extra_configuration_before_yield():
    """
    Disable syscheck.rt_delay internal option
    """
    disable_rt_delay()


def extra_configuration_after_yield():
    """
    Restore syscheck.rt_delay internal option
    """
    restore_rt_delay()


# Tests

@pytest.mark.parametrize('tags_to_apply', [
    {'ossec_conf_diff_default'}
])
@pytest.mark.parametrize('filename, folder', [
    ('regular_0', testdir1),
])
def test_file_size_default(tags_to_apply, filename, folder, get_configuration, configure_environment, restart_syscheckd,
                           wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon limits the size of the monitored file to generate
                 'diff' information from the default value of the 'file_size' option. For this purpose,
                 the test will monitor a directory, create a testing file smaller than the default limit,
                 and check if the compressed file has been created. Then, it will increase the size of
                 the testing file. Finally, the test will verify that the FIM event related to the
                 reached file size limit has been generated, and the compressed file in the 'queue/diff/local'
                 directory does not exist.

    wazuh_min_version: 4.2.0

    parameters:
        - tags_to_apply:
            type: set
            brief: Run test if matches with a configuration identifier, skip otherwise.
        - filename:
            type: str
            brief: Name of the testing file to be created.
        - folder:
            type: str
            brief: Path to the directory where the testing files are being created.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.

    assertions:
        - Verify that the 'diff' folder is created when a monitored file does not exceed the size limit.
        - Verify that FIM events are generated indicating the size limit reached of monitored files
          to generate 'diff' information with the default limit of the 'file_size' tag (50MB).
        - Verify that the 'diff' folder is removed when a monitored file exceeds the size limit.

    input_description: A test case (ossec_conf_diff_default) is contained in external YAML
                       file (wazuh_conf.yaml) which includes configuration settings for
                       the 'wazuh-syscheckd' daemon and, these are combined with the
                       testing directory to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added' events)
        - r'.*File .* is too big for configured maximum size to perform diff operation'

    tags:
        - diff
        - scheduled
        - time_travel
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    size_limit = translate_size('50MB')
    diff_file_path = make_diff_file_path(folder=folder, filename=filename)

    # Create file with a smaller size than the configured value
    to_write = generate_string(int(size_limit / 10), '0')
    create_file(REGULAR, folder, filename, content=to_write)

    check_time_travel(scheduled)
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                            error_message='Did not receive expected "Sending FIM event: ..." event.')

    if not os.path.exists(diff_file_path):
        pytest.raises(FileNotFoundError(f"{diff_file_path} not found. It should exist before increasing the size."))

    # Increase the size of the file over the configured value
    to_write = generate_string(size_limit, '0')
    modify_file_content(folder, filename, new_content=to_write * 3)

    check_time_travel(scheduled)

    wazuh_log_monitor.start(
        timeout=global_parameters.default_timeout,
        callback=callback_file_size_limit_reached,
        error_message='Did not receive expected '
                      '"File ... is too big for configured maximum size to perform diff operation" event.')

    if os.path.exists(diff_file_path):
        pytest.raises(FileExistsError(f"{diff_file_path} found. It should not exist after incresing the size."))

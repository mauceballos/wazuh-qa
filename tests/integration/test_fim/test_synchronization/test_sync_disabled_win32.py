'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if FIM disables the synchronization
       of file/registry on Windows systems when the 'enabled' tag of the synchronization option is
       set to 'no', and vice versa.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

tier: 1

modules:
    - fim

components:
    - agent

daemons:
    - wazuh-syscheckd

os_platform:
    - windows

os_version:
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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#synchronization

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_synchronization
'''
import os

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, callback_detect_integrity_event, generate_params
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=1)]

# variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
key = "HKEY_LOCAL_MACHINE"
subkey = "SOFTWARE\\test"

configurations_path = os.path.join(test_data_path, 'wazuh_disabled_sync_conf_win32.yaml')

test_directories = [os.path.join(PREFIX, 'testdir1')]
test_regs = [os.path.join(key, subkey)]

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

conf_params = {'TEST_DIRECTORIES': test_directories[0],
               'TEST_REGISTRIES': test_regs[0]}

# configurations

p, m = generate_params(extra_params=conf_params, modes=['scheduled', 'realtime', 'whodata'])

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests


@pytest.mark.parametrize('tags_to_apply, file_sync, registry_sync, ', [
    ({'sync_disabled'}, False, False),
    ({'sync_registry_disabled'}, True, False),
    ({'sync_registry_enabled'}, True, True)
])
def test_sync_disabled(tags_to_apply, file_sync, registry_sync,
                       get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start_sync_disabled):
    '''
    description: Check if the 'wazuh-syscheckd' daemon uses the value of the 'enabled' tag to start/stop
                 the file/registry synchronization. For this purpose, the test will monitor a directory/key.
                 Finally, it will verify that no FIM 'integrity' event is generated when the synchronization
                 is disabled, and verify that the FIM 'integrity' event generated corresponds with a
                 file or a registry when the synchronization is enabled, depending on the test case.

    wazuh_min_version: 4.2.0

    parameters:
        - tags_to_apply:
            type: set
            brief: Run test if matches with a configuration identifier, skip otherwise.
        - file_sync:
            type: bool
            brief: True if file synchronization is enabled. False otherwise.
        - registry_sync:
            type: bool
            brief: True if registry synchronization is enabled. False otherwise.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.
        - wait_for_fim_start_sync_disabled:
            type: fixture
            brief: Wait for end of initial FIM scan.

    assertions:
        - Verify that no FIM 'integrity' events are generated when the value
          of the 'enabled' tag is set yo 'no' (synchronization disabled).
        - Verify that FIM 'integrity' events generated correspond to a file/registry depending on
          the value of the 'enabled' and the 'registry_enabled' tags (synchronization enabled).

    input_description: Different test cases are contained in external YAML file (wazuh_disabled_sync_conf_win32.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon. That is combined with
                       the testing directory/key to be monitored defined in this module.

    expected_output:
        - r'.*Sending integrity control message'

    tags:
        - scheduled
        - time_travel
        - realtime
        - who_data
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    if not file_sync:
        # The file synchronization event shouldn't be triggered
        with pytest.raises(TimeoutError):
            event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                            callback=callback_detect_integrity_event, update_position=True).result()
    else:
        # The file synchronization event should be triggered
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                                        callback=callback_detect_integrity_event, update_position=True).result()
        assert event['component'] == 'fim_file', 'Wrong event component'

    if not registry_sync:
        # The registry synchronization event shouldn't be triggered
        with pytest.raises(TimeoutError):
            event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, update_position=True,
                                            callback=callback_detect_integrity_event).result()
    else:
        # The registry synchronization event should be triggered
        event = wazuh_log_monitor.start(timeout=global_parameters.default_timeout, update_position=True,
                                        callback=callback_detect_integrity_event).result()
        assert event['component'] == 'fim_registry', 'Wrong event component'

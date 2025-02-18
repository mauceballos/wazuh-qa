'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts
       when these files are modified. Specifically, these tests will check if FIM events are
       generated when environment variables are used to monitor directories in Windows systems.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

tier: 2

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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#directories

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_env_variables
'''
import os
import sys

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, regular_file_cud
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor

# Marks
pytestmark = [pytest.mark.win32, pytest.mark.tier(level=2)]

# Variables and configuration
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir1', 'subdir')]
dir1, subdir1 = test_directories

environment_variables = [("TEST_ENV_VAR", dir1)]
test_env = "%TEST_ENV_VAR%"

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_dir.yaml')
mark_skip_agentWindows = pytest.mark.skipif(sys.platform == 'win32', reason="It will be blocked by wazuh/wazuh-qa#2174")

conf_params = {'TEST_ENV_VARIABLES': test_env, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params)

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixture
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Test
@pytest.mark.parametrize('directory', [subdir1])
@mark_skip_agentWindows
def test_tag_directories(directory, get_configuration, put_env_variables, configure_environment,
                         restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects CUD events ('added', 'modified', and 'deleted')
                 when environment variables are used to monitor directories. For this purpose, the test
                 will monitor a directory that is defined in an environment variable. Then, different
                 operations will be performed on testing files, and finally, the test will verify
                 that the proper FIM events have been generated.

    wazuh_min_version: 4.2.0

    parameters:
        - directory:
            type: str
            brief: Path to the directory to be monitored.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - put_env_variables:
            type: fixture
            brief: Create the environment variables.
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
        - Verify that FIM events are generated when environment variables are used to monitor directories.

    input_description: A test case (ossec_conf) is contained in external YAML file (wazuh_conf_dir.yaml) which
                       includes configuration settings for the 'wazuh-syscheckd' daemon and, it is combined
                       with the directory to be monitored defined as an environment variable in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
        - time_travel
    '''
    regular_file_cud(directory, wazuh_log_monitor, file_list=["testing_env_variables"],
                     min_timeout=global_parameters.default_timeout,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled')

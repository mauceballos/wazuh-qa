'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if FIM watches selected
       files and triggering alerts when these files are modified. All these tests will be performed
       using complex paths and ambiguous configurations, such as keys and subkeys with opposite
       monitoring settings. In particular, it will verify that the value of the 'ignore' attribute
       prevails over the 'restrict' one.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#registry-ignore

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_registry_ambiguous_confs
'''
import os

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, registry_value_cud, registry_key_cud, \
    KEY_WOW64_32KEY, KEY_WOW64_64KEY, generate_params
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=2)]

# Variables

key = "HKEY_LOCAL_MACHINE"
subkey_1 = "SOFTWARE\\testkey1"
subkey_2 = "SOFTWARE\\testkey2"

test_regs = [os.path.join(key, subkey_1),
             os.path.join(key, subkey_2)
             ]

conf_params = {'WINDOWS_REGISTRY_1': test_regs[0],
               'WINDOWS_REGISTRY_2': test_regs[1],
               'RESTRICT_KEY_1': "restrict_key$",
               'RESTRICT_KEY_2': "key_restrict$",
               'REGISTRY_IGNORE': os.path.join(test_regs[0], "restrict_key"),
               'REGISTRY_IGNORE_REGEX': 'key_restrict$',
               'RESTRICT_VALUE_1': 'restrict_value$',
               'RESTRICT_VALUE_2': 'value_restrict$',
               'REGISTRY_IGNORE_VALUE': os.path.join(test_regs[0], "restrict_value"),
               'REGISTRY_IGNORE_VALUE_REGEX': 'value_restrict$'
               }

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_ignore_over_restrict.yaml')

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
p, m = generate_params(extra_params=conf_params, modes=['scheduled'])

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.parametrize('key, subkey, arch, key_name', [
    (key, subkey_1, KEY_WOW64_64KEY, 'restrict_key'),
    (key, subkey_1, KEY_WOW64_64KEY, 'key_restrict'),
    (key, subkey_2, KEY_WOW64_64KEY, 'key_restrict'),
    (key, subkey_2, KEY_WOW64_32KEY, 'key_restrict')
])
def test_ignore_over_restrict_key(key, subkey, key_name, arch,
                                  get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'ignore' tag prevails over the 'restrict' one when using both in the same
                 registry key. For example, when a registry key is ignored, and at the same time,
                 monitoring is restricted on other key that is in that key, no FIM events should be generated
                 when that key is modified. For this purpose, the test will monitor a registry key that
                 is ignored in the configuration, and make key operations inside it. Finally, it will verify
                 that no FIM events are generated.

    wazuh_min_version: 4.2.0

    parameters:
        - key:
            type: str
            brief: Path of the registry root key (HKEY_* constants).
        - sub_key:
            type: str
            brief: Path of the key that will be created under the root key.
        - key_name:
            type: str
            brief: Name of the testing key that will be used to make CUD operations.
        - arch:
            type: str
            brief: Architecture of the registry.
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
        - Verify that when a registry key is ignored, the 'restrict' attribute
          is not taken into account to generate FIM events.

    input_description: A test case (ambiguous_ignore_restrict_key) is contained in an external YAML file
                       (wazuh_ignore_over_restrict.yaml) which includes configuration settings for
                       the 'wazuh-syscheckd' daemon. That is combined with the testing registry keys
                       to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' (at end of the initial FIM scan)

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test({"ambiguous_ignore_restrict_key"}, get_configuration['tags'])

    # Test registry keys.
    registry_key_cud(key, subkey, wazuh_log_monitor, arch=arch, key_list=[key_name],
                     min_timeout=global_parameters.default_timeout, time_travel=True, triggers_event=False)


@pytest.mark.parametrize('key, subkey, arch, value_name', [
    (key, subkey_1, KEY_WOW64_64KEY, 'restrict_value'),
    (key, subkey_1, KEY_WOW64_64KEY, 'value_restrict'),
    (key, subkey_2, KEY_WOW64_64KEY, 'value_restrict'),
    (key, subkey_2, KEY_WOW64_32KEY, 'value_restrict')
])
@pytest.mark.skip(reason="It will be blocked by #1602, when it was solve we can enable again this test")
def test_ignore_over_restrict_values(key, subkey, value_name, arch,
                                     get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'ignore' tag prevails over the 'restrict' one when using both in the same
                 registry key. For example, when a registry key is ignored, and at the same time,
                 monitoring is restricted on a value that is in that key, no FIM events should be generated
                 when that value is modified. For this purpose, the test will monitor a registry key that
                 is ignored in the configuration, and make value operations inside it. Finally, it will verify
                 that no FIM events are generated.

    wazuh_min_version: 4.2.0

    parameters:
        - key:
            type: str
            brief: Path of the registry root key (HKEY_* constants).
        - sub_key:
            type: str
            brief: Path of the key that will be created under the root key.
        - value_name:
            type: str
            brief: Value of the testing key that will be used to make CUD operations.
        - arch:
            type: str
            brief: Architecture of the registry.
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
        - Verify that when a registry key is ignored, the 'restrict' attribute
          is not taken into account to generate FIM events.

    input_description: A test case (ambiguous_ignore_restrict_values) is contained in an external YAML file
                       (wazuh_ignore_over_restrict.yaml) which includes configuration settings for
                       the 'wazuh-syscheckd' daemon. That is combined with the testing registry keys
                       to be monitored defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' (at end of the initial FIM scan)

    tags:
        - scheduled
        - time_travel
    '''
    check_apply_test({"ambiguous_ignore_restrict_values"}, get_configuration['tags'])

    # Test registry keys.
    registry_value_cud(key, subkey, wazuh_log_monitor, arch=arch, value_list=[value_name],
                       min_timeout=global_parameters.default_timeout, time_travel=True, triggers_event=False)

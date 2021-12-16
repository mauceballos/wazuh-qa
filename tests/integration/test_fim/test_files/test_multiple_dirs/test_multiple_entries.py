'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts
       when these files are modified. Specifically, these tests will check if FIM detects
       all file modification events when monitoring the maximum number of directories (64)
       set using multiple 'directories' tags.
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
    - fim_multiple_dirs
'''
import os
from sys import platform
import sys

import pytest
import yaml
from test_fim.test_files.test_multiple_dirs.common import multiple_dirs_test
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=1)

# variables

n_dirs = 64
test_directories = [os.path.join(PREFIX, f'testdir{i}') for i in range(n_dirs)]
directory_str = ','.join(test_directories)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'multiple_entries.yaml')


def create_yaml(n_dirs=0):
    """Create a new YAML with the required WILDCARDS for every directory in `test_directories`.

    Parameters
    ----------
    n_dirs : int, optional
        Number of created/monitored directories. Default `0`
    """
    with open(os.path.join(test_data_path, 'multiple_entries.yaml'), 'w') as f:
        dikt = [
            {
                'tags': ['multiple_dir_entries'],
                'apply_to_modules': ['test_multiple_entries'],
                'sections': [
                    {'section': 'syscheck',
                     'elements':
                         [
                             {'disabled': {'value': 'no'}},
                         ]
                     }
                ]
            }
        ]

        for new_dir in ({'directories': {'value': f'DIR{i}', 'attributes': ['FIM_MODE']}} for i in range(n_dirs)):
            dikt[0]['sections'][0]['elements'].append(new_dir)
        f.write(yaml.safe_dump(dikt, sort_keys=False))


# configurations

create_yaml(n_dirs=len(test_directories))
conf_params = {f'DIR{i}': testdir for i, testdir in enumerate(test_directories)}
conf_params['MODULE_NAME'] = __name__
p, m = generate_params(extra_params=conf_params)

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.skipif(sys.platform == 'win32', reason="Blocked by issue wazuh-qa#2174, when it is solved we can enable this test again")
@pytest.mark.parametrize('dir_list, tags_to_apply', [
    (test_directories, {'multiple_dir_entries'})
])
def test_cud_multiple_dir_entries(dir_list, tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                                  wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects every event when adding, modifying, and deleting
                 a testing file within each one of the monitored directories. Also, it verifies that it can monitor
                 the maximum allowed number of folders using multiple 'directories' tags (64). For this purpose,
                 the test will monitor multiple folders and make file operations inside them. Then, it will check
                 if all FIM events are generated for each file operation made. Finally, the test will verify that
                 the number of FIM events generated corresponds with the monitored directories.

    wazuh_min_version: 4.2.0

    parameters:
        - dir_list:
            type: list
            brief: List with the directories to be monitored.
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

    assertions:
        - Verify that FIM events are generated for all monitored folders set
          in multiple 'directories' (up to a limit of 64).

    input_description: A test case (multiple_dir_entries) is contained in external YAML file
                       (multiple_entries.yaml) which includes configuration settings for
                       the 'wazuh-syscheckd' daemon and testing directories to be monitored.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)

    tags:
        - scheduled
        - who_data
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    file = 'regular'
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    whodata = get_configuration['metadata']['fim_mode'] == 'whodata'

    try:
        multiple_dirs_test(mode="entries", dir_list=dir_list, file=file, scheduled=scheduled, whodata=whodata,
                           log_monitor=wazuh_log_monitor, timeout=2 * global_parameters.default_timeout)
    except TimeoutError as e:
        if whodata:
            pytest.xfail(reason='Xfailed due to issue: https://github.com/wazuh/wazuh/issues/4731')
        else:
            raise e

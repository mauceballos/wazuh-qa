# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import sys
from json import load
import tempfile

import pytest
import wazuh_testing.tools.configuration as conf
from wazuh_testing import logcollector
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools import LOGCOLLECTOR_STATISTICS_FILE
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service

from time import sleep

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=1), pytest.mark.server]

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'configuration')
configurations_path = os.path.join(test_data_path, 'wazuh_configuration.yaml')

temp_dir = tempfile.gettempdir()

file_structure = [
    {
        'folder_path': os.path.join(temp_dir, 'wazuh-testing'),
        'filename': ['test.txt'],
        'content': f'Content of testing_file\n'
    }
]

parameters = [
    {'LOCATION': os.path.join(temp_dir, 'wazuh-testing', 'test.txt'), 'LOG_FORMAT': 'syslog'},
]

metadata = [
    {'location': os.path.join(temp_dir, 'wazuh-testing', 'test.txt'), 'log_format': 'syslog'}
]

# Configuration data
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['LOCATION']}_{x['LOG_FORMAT']}" for x in parameters]
local_options = [{'state_interval': '1', 'open_attempts': '1'},
                 {'state_interval': '4', 'open_attempts': '4'},
                 {'state_interval': '5', 'open_attempts': '10'}]
local_internal_options = {'logcollector.debug': '2'}


# Fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope="module")
def get_files_list():
    """Get file list to create from the module."""
    return file_structure


@pytest.fixture(scope="function", params=local_options)
def get_local_internal_options_function(request):
    """Get configurations from the module."""
    backup_options_lines = conf.get_wazuh_local_internal_options()
    conf.add_wazuh_local_internal_options({'logcollector.open_attempts': request.param['open_attempts'],
                                           'logcollector.state_interval': request.param['state_interval'],
                                           'logcollector.vcheck_files': '3'})
    yield request.param

    conf.set_wazuh_local_internal_options(backup_options_lines)


@pytest.mark.skip(reason="Unexpected false positive, further investigation is required")
def test_options_state_interval_no_file(configure_local_internal_options_module, get_local_internal_options_function,
                                        get_files_list, create_file_structure_function,
                                        get_configuration, configure_environment):
    """Check if the monitorized file does not appear in logcollector.state when it is removed.

    Raises:
        AssertionError: If the elapsed time is different from the interval.
        TimeoutError: If the expected callback is not generated.
    """
    truncate_file(LOG_FILE_PATH)
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    control_service("restart")

    interval = int(get_local_internal_options_function['state_interval'])
    open_attempts = int(get_local_internal_options_function['open_attempts'])
    logcollector_state_file_updated = False

    for file in get_files_list:
        for name in file['filename']:
            # Ensure file is analyzed
            log_path = os.path.join(file['folder_path'], name)
            with open(log_path, 'w') as log_file:
                log_file.write('Modifying the file\n')

            log_callback = logcollector.callback_analyzing_file(log_path)
            wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                    error_message=logcollector.GENERIC_CALLBACK_ERROR_ANALYZING_FILE)

            # Ensure wazuh-logcollector.state is created
            logcollector.wait_statistics_file(timeout=interval + 5)

            with open(LOGCOLLECTOR_STATISTICS_FILE, 'r') as json_file:
                data = load(json_file)

            global_files = data['global']['files']
            interval_files = data['interval']['files']

            assert list(filter(lambda global_file: global_file['location'] == log_path, global_files))
            assert list(filter(lambda interval_file: interval_file['location'] == log_path, interval_files))

            os.remove(log_path)

            log_callback = logcollector.callback_removed_file(log_path)
            wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                    error_message="File no longer exists has not been generated")

            for n_attempts in range(open_attempts):
                log_callback = logcollector.callback_unable_to_open(log_path, open_attempts - (n_attempts + 1))
                wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                        error_message="Unable to open file callback has not been generated")

            log_callback = logcollector.callback_ignored_removed_file(log_path)
            wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                    error_message="File not available callback has not been generated")

            # Wait 62 seconds, the max time that logcollector may take to delete the file from the statistics file.
            for _ in range(62):
                with open(LOGCOLLECTOR_STATISTICS_FILE, 'r') as next_json_file:
                    data = load(next_json_file)

                try:
                    global_files = data['global']['files']
                    interval_files = data['interval']['files']
                    if not list(filter(lambda global_file: global_file['location'] == log_path, global_files)) and \
                            not list(filter(lambda interval_file: interval_file['location'] == log_path, interval_files)):
                        logcollector_state_file_updated = True
                        break
                    else:
                        sleep(1)
                except KeyError:
                    assert len(data) == 0
                    logcollector_state_file_updated = True

            assert logcollector_state_file_updated

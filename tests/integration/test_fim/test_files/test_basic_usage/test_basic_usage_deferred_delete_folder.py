# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from subprocess import Popen, PIPE, DEVNULL
import re
import json
from json import JSONDecodeError

import pytest

from wazuh_testing import global_parameters, logger
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, create_file, REGULAR, callback_detect_event
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=0)]

# variables

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2')]
directory_str = ','.join(test_directories)
for direc in list(test_directories):
    test_directories.append(os.path.join(direc, 'subdir'))
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1, testdir2 = test_directories[2:]

# configurations

conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params, modes=['whodata'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# callback
def callback_detect_delete_event(line):
    msg = r'.*Sending FIM event: (.+)$'
    print(type(msg))
    print(msg)
    print("\n\n")
    print("########################################################\n")
   
    print(type(line))
    print(line)
    print("\n\n")
    print("########################################################\n")

    match = re.match(msg, line)
    print(type(match))
    print(match)
    print("\n\n")
    print("########################################################\n")

    if not match:
        return None

    paso(11)
    try:
        paso(12)
        event = json.loads(match.group(1))
        paso(18)
        if (event['type'] == 'event' and
                event['data']['type'] == 'deleted' and
                'process_name' not in event['data']['audit']):
            paso(13)
            return event
        paso(14)
    # except (AttributeError, JSONDecodeError, KeyError):
    #     paso(15)
    #     pass
    # paso(16)
    # return None
    except (JSONDecodeError, AttributeError, KeyError) as e:
        paso(15)
        logger.warning(f"Couldn't load a log line into json object. Reason {e}")
    paso(16)
# fixtures


@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    paso(17)
    return request.param


# tests
@pytest.mark.parametrize('folder, file_list, filetype, tags_to_apply', [
    (testdir1, ['regular0', 'regular1', 'regular2'], REGULAR, {'ossec_conf'},),
    (testdir2, ['regular0', 'regular1', 'regular2'], REGULAR, {'ossec_conf'},)
])
def test_deferred_delete_file(folder, file_list, filetype, tags_to_apply,
                              get_configuration, configure_environment,
                              restart_syscheckd, wait_for_fim_start):
    """
    Check if syscheckd detects 'deleted' events from the files contained
    in a folder that are deleted in a deferred manner.

    We first run the command in order to find the confirmation character in the os,
    after that we delete the files

    The events generated must not contain the process_name parameter in order to guarantee
    it's a 4659 event that generated it

    Parameters
    ----------
    folder : str
        Directory where the files will be created.
    file_list : list
        Names of the files.
    filetype : str
        Type of the files that will be created.
    """
    paso(0)
    check_apply_test(tags_to_apply, get_configuration['tags'])
    print(type(tags_to_apply))
    paso(1)
    # Create files inside subdir folder
    for file in file_list:
        create_file(filetype, folder, file, content='')
    paso(2)
    # Wait for the added events
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                            accum_results=len(file_list), error_message='Did not receive expected '
                            '"Sending FIM event: ..." event')
    paso(3)
    # Delete the files under 'folder'
    command = 'del "{}"\n'.format(folder)
    paso(4)
    cmd = Popen(command, shell=True, stdin=PIPE, stdout=PIPE, stderr=DEVNULL, universal_newlines=True)
    try:
        stdout = cmd.communicate(timeout=global_parameters.default_timeout)
        paso(5)
    except TimeoutError:
        paso(6)
        pass

    # Find the windows confirmation character
    confirmation = re.search(r'\((\w)\/\w\)\?', stdout[0])
    assert confirmation
    paso(7)
    # Run the command again and this time delete the files
    cmd = Popen(command, shell=True, stdin=PIPE, stdout=PIPE, stderr=DEVNULL, universal_newlines=True)
    try:
        stdout = cmd.communicate('{}\n'.format(confirmation.group(1)), timeout=global_parameters.default_timeout)
        paso(8)
    except TimeoutError:
        paso(9)
        pass

    # Start monitoring
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_delete_event,
                            accum_results=len(file_list), error_message='Did not receive expected '
                            '"Sending FIM event: ..." event')
    paso(10)


def paso(nro):
    print("\n\n")
    print("################## - PASO " + str(nro) + " - ##################")
    print("\n\n")
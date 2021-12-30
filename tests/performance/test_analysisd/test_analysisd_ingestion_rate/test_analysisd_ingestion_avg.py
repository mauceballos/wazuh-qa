'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: performance

brief: The 'wazuh-analysisd' daemon receives a log message and if it matches
       an applicable rule then the daemon creates an alert. The analysisd queue
       socket receives the message and sends it to the respective decoder
       queue, and if the selected queue is full the event is dropped.
       This test aims to compare the average of dropped events before and after
       the upgrade of the manager, and checks if the ingestion rate does
       not decrease.

tier: 0

modules:
    - analysisd

components:
    - manager

daemons:
    - wazuh-analysisd

os_platform:
    - linux
    - windows
    - macos
    - solaris

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
    - macOS Catalina
    - Solaris 10
    - Solaris 11

references:
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html

tags:
    - analysisd_performance
    - analysisd_ingestion_rate
'''

import pytest
import os

from wazuh_testing.tools.file import validate_json_file, read_json_file
from wazuh_testing.tools.file import write_json_file
from wazuh_testing.tools.time import get_current_timestamp


@pytest.fixture
def get_first_result(request):
    """Allow to use the --before-file parameter in order to pass the results
    path before upgrading Wazuh.

    Args:
        request (fixture): Provide information on the executing test function.
    """
    return request.config.getoption('--before-results')


@pytest.fixture
def get_second_result(request):
    """Allow to use the --after-file parameter in order to pass the results
    path after upgrading Wazuh.

    Args:
        request (fixture): Provide information on the executing test function.
    """
    return request.config.getoption('--after-results')


@pytest.fixture
def get_output_path(request):
    """Allow to use the --output-path parameter to store the test result in
    the specified file.

    Args:
        request (fixture): Provide information on the executing test function.
    """
    return request.config.getoption('--output-path')


def validate_and_read_json(file_path):
    """Validate the JSON file passed as argument and return its content.

    Args:
        file_path (str): JSON file path.

    Returns:
        The JSON file content.

    Raises:
        ValueError: If the given file is not valid.
    """
    if validate_json_file(file_path):
        file_data = read_json_file(file_path)
    else:
        raise ValueError(f"The file {file_path} is not a valid JSON.")

    return file_data


def validate_and_create_output_path(output_path):
    """"Check that the given output path is a directory if it already exists and creates it when it does not exist yet.
    Args:
        output_path (str): Path were the results will be saved.
    """
    try:
        if os.path.exists(output_path) and not os.path.isdir(output_path):
            raise ValueError(f"The given output path {output_path} already exists and is not a directory.")
    except TypeError:
        raise TypeError(f"The --output-path flag expects a string with the path where you want to save the test "
                        "results.")

    if not os.path.exists(output_path):
        os.makedirs(output_path)


def test_analysisd_ingestion_rate(get_first_result, get_second_result,
                                  get_output_path):
    '''
    description: This test aims to compare the average of dropped events before and after
                 the upgrade of the manager, and checks if the ingestion rate does
                 not decrease.

    wazuh_min_version: 4.2.0

    parameters:
        - get_first_result:
            type: fixture
            brief: Get the file path of the results before upgrading Wazuh.
        - get_second_result:
            type: fixture
            brief: Get the file path of the results after upgrading Wazuh.
        - get_output_path:
            type: fixture
            brief: Get the file path where the test result will be stored.
    
    assertions:
        - Verify that the ingestion rate does not decreased after upgrading
          Wazuh.

    input_description: The results of stress analysisd, before and after
                       upgrading Wazuh, are stored in 2 files. They contain
                       the necessary data for the test to compare them.

    expected_output:
        - A JSON with the result of the test.
        - The ingestion rate decreased after the upgrade,
          check the results within /path/to/result/file

    tags:
        - analysisd_performance
        - ingestion_rate
    '''
    file1_data = validate_and_read_json(get_first_result)
    file2_data = validate_and_read_json(get_second_result)
    validate_and_create_output_path(get_output_path)

    initial_drop_average = int(file1_data['Average']['Dropped'])
    final_drop_average = int(file2_data['Average']['Dropped'])

    threshold = 20

    if initial_drop_average == final_drop_average:
        drop_variation = 0
    elif initial_drop_average != 0:
        if final_drop_average > initial_drop_average:
            drop_variation = (
                (final_drop_average - initial_drop_average) 
                / initial_drop_average) * 100
        elif final_drop_average != 0:
            drop_variation = -(
                (initial_drop_average - final_drop_average)
                / initial_drop_average) * 100
    elif initial_drop_average == 0:
        drop_variation = 100
    else:
        drop_variation = -100

    result_text = (('increased ' if drop_variation > 0 else 'decreased ') \
                    + f'{drop_variation}%') if drop_variation != 0 \
                    else 'remained'
    interpretation = 'The dropped average ' + result_text

    result_data = {
        'Before': file1_data,
        'After': file2_data,
        '% Variation': drop_variation,
        'Interpretation': interpretation
    }
    current_timestamp = str(get_current_timestamp()).replace('.', '_')
    results_path = os.path.join(get_output_path, f'test_results_{current_timestamp}.json')
    write_json_file(results_path, result_data)

    assert not drop_variation >= threshold, "The ingestion rate decreased" \
                                            "after the upgrade," \
                                            f"check the results within {get_output_path}"

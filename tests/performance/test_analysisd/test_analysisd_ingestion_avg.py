# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest

from wazuh_testing.tools.file import validate_json_file, read_json_file


@pytest.fixture
def get_first_file(request):
    """Allow to use the --before-file parameter in order to pass the results before upgrade Wazuh.

    Args:
        request (fixture): Provide information on the executing test function.
    """
    return request.config.getoption('--before-results')


@pytest.fixture
def get_second_file(request):
    """Allow to use the --after-file parameter in order to pass the results after upgrade Wazuh.

    Args:
        request (fixture): Provide information on the executing test function.
    """
    return request.config.getoption('--after-results')


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


def test_analysisd_ingestion_rate(get_first_file, get_second_file):
    file1_data = validate_and_read_json(get_first_file)
    file2_data = validate_and_read_json(get_second_file)

# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import subprocess as sb
import pytest
from wazuh_testing import logger
import wazuh_testing.tools.configuration as conf
from wazuh_testing.tools import WAZUH_LOCAL_INTERNAL_OPTIONS


@pytest.fixture(scope='module')
def configure_local_internal_options_module(request):
    """Fixture to configure the local internal options file.
    It uses the test variable local_internal_options. This should be
    a dictionary wich keys and values corresponds to the internal option configuration, For example:
    local_internal_options = {'monitord.rotate_log': '0', 'syscheck.debug': '0' }
    """
    try:
        local_internal_options = getattr(request.module, 'local_internal_options')
    except AttributeError as local_internal_configuration_not_set:
        logger.debug('local_internal_options is not set')
        raise local_internal_configuration_not_set

    backup_local_internal_options = conf.get_local_internal_options_dict()

    logger.debug(f"Set local_internal_option to {str(local_internal_options)}")
    conf.set_local_internal_options_dict(local_internal_options)

    yield

    logger.debug(f"Restore local_internal_option to {str(backup_local_internal_options)}")
    conf.set_local_internal_options_dict(backup_local_internal_options)

# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

'''
The purpose of this file is to contain all the variables necessary for Wazuh in order to be easier
to maintain if one of them changes in the future.
'''

import pytest

# Local internal options
WINDOWS_DEBUG = 'windows.debug'
VERBOSE_DEBUG_OUTPUT = 2

# Action Services

WAZUH_SERVICES_STOP = 'stop'
WAZUH_SERVICES_START = 'start'

# Configurations
DATA = 'data'
WAZUH_LOG_MONITOR = 'wazuh_log_monitor'

# Marks Executions
TIER1 = pytest.mark.tier(level=1)
AGENT = pytest.mark.agent
WINDOWS = pytest.mark.win32
LINUX = pytest.mark.linux
import os
import pytest
from yaml import safe_load
from shutil import copy

from wazuh_testing import global_parameters
from wazuh_testing.tools.services import control_service
from wazuh_testing.logcollector import LOG_COLLECTOR_GLOBAL_TIMEOUT
from wazuh_testing.logtest import callback_logtest_started
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH
from wazuh_testing.analysis import (callback_analysisd_invalid_value,
                                    callback_analysisd_deprecated_value)


# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_path = os.path.join(test_data_path, 'decoder_syntax_json_fields.yaml')
with open(messages_path) as f:
    test_cases = safe_load(f)

# Variables
logtest_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'sockets', 'logtest'))
receiver_sockets_params = [(logtest_path, 'AF_UNIX', 'TCP')]

callbacks = {
    'invalid_value': callback_analysisd_invalid_value,
    'deprecated_value': callback_analysisd_deprecated_value
}
 


# Fixtures
@pytest.fixture(scope='function')
def configure_local_decoders(get_configuration):
    """Configure a custom decoder for testing."""

    # configuration for testing
    decoder_file_test = os.path.join(test_data_path, get_configuration['decoder'])
    decoder_target_file_test = os.path.join(WAZUH_PATH, 'etc', 'decoders', get_configuration['decoder'])

    copy(decoder_file_test, decoder_target_file_test)

    yield

    # restore previous configuration
    os.remove(decoder_target_file_test)

@pytest.fixture(scope='function')
def configure_local_rules(get_configuration):
    """Configure a custom rule for testing"""

    # configuration for testing
    rule_file_test = os.path.join(test_data_path, get_configuration['rules'])
    rule_target_file_test = os.path.join(WAZUH_PATH, 'etc', 'rules', get_configuration['rules'])
    copy(rule_file_test, rule_target_file_test)

    yield

    # restore previous configuration
    os.remove(rule_target_file_test)

@pytest.fixture(scope='function', params=test_cases, ids=[test_case['name'] for test_case in test_cases])
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope='function')
def restart_required_logtest_daemons():
    """Wazuh logtests daemons handler."""
    required_logtest_daemons = ['wazuh-analysisd', 'wazuh-db']

    for daemon in required_logtest_daemons:
        control_service('stop', daemon=daemon)

    truncate_file(LOG_FILE_PATH)

    for daemon in required_logtest_daemons:
        control_service('start', daemon=daemon)

    yield

    for daemon in required_logtest_daemons:
        control_service('stop', daemon=daemon)


@pytest.fixture(scope='function')
def wait_for_logtest_startup(request):
    """Wait until logtest has begun."""
    log_monitor = FileMonitor(LOG_FILE_PATH)
    log_monitor.start(timeout=LOG_COLLECTOR_GLOBAL_TIMEOUT, callback=callback_logtest_started)


# Test
def test_decoder_syntax(get_configuration, configure_local_decoders, 
                        configure_local_rules,
                        restart_required_logtest_daemons,
                        wait_for_logtest_startup,
                        connect_to_sockets_function):

    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout,
                            callback=callbacks.get(get_configuration['log_expect']),
                            error_message='Event not found')
    assert wazuh_log_monitor.result()

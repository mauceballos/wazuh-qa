import pytest
import os
import yaml

from wazuh_testing.tools import LOG_FILE_PATH, CLIENT_KEYS_PATH, API_LOG_FILE_PATH
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor, make_callback, AUTHD_DETECTOR_PREFIX
from wazuh_testing.tools.configuration import write_wazuh_conf, get_wazuh_conf, set_section_wazuh_conf,\
                                              load_wazuh_configurations                                      
from wazuh_testing.tools.services import control_service, check_daemon_status, delete_dbs
from wazuh_testing.tools.monitoring import QueueMonitor
from wazuh_testing.authd import DAEMON_NAME
from wazuh_testing.api import callback_detect_api_start, get_api_details_dict


AUTHD_STARTUP_TIMEOUT = 30


def truncate_client_keys_file():
    """
    Cleans any previous key in client.keys file.
    """
    try:
        control_service("stop", DAEMON_NAME)
    except Exception:
        pass
    truncate_file(CLIENT_KEYS_PATH)


@pytest.fixture(scope='function')
def clean_client_keys_file_function():
    """
    Cleans any previous key in client.keys file at function scope.
    """
    truncate_client_keys_file()


@pytest.fixture(scope='module')
def clean_client_keys_file_module():
    """
    Cleans any previous key in client.keys file at module scope.
    """
    truncate_client_keys_file()


@pytest.fixture(scope='module')
def restart_authd(get_configuration):
    """
    Restart Authd.
    """
    truncate_file(LOG_FILE_PATH)
    control_service("restart", daemon=DAEMON_NAME)


@pytest.fixture(scope='function')
def restart_authd_function():
    """
    Restart Authd.
    """
    truncate_file(LOG_FILE_PATH)
    control_service("restart", daemon=DAEMON_NAME)


@pytest.fixture(scope='function')
def stop_authd_function():
    """
    Stop Authd.
    """
    control_service("stop", daemon=DAEMON_NAME)


@pytest.fixture(scope='module')
def wait_for_authd_startup_module(get_configuration):
    """Wait until authd has begun"""
    log_monitor = FileMonitor(LOG_FILE_PATH)
    log_monitor.start(timeout=AUTHD_STARTUP_TIMEOUT,
                      callback=make_callback('Accepting connections on port 1515', prefix=AUTHD_DETECTOR_PREFIX,
                                             escape=True),
                      error_message='Authd doesn´t started correctly.')


@pytest.fixture(scope='function')
def wait_for_authd_startup_function():
    """Wait until authd has begun with function scope"""
    log_monitor = FileMonitor(LOG_FILE_PATH)
    log_monitor.start(timeout=AUTHD_STARTUP_TIMEOUT,
                      callback=make_callback('Accepting connections on port 1515', prefix=AUTHD_DETECTOR_PREFIX,
                                             escape=True),
                      error_message='Authd doesn´t started correctly.')


@pytest.fixture(scope='module')
def tear_down():
    """
    Roll back the daemon and client.keys state after the test ends.
    """
    yield
    # Stop Wazuh
    control_service('stop')
    truncate_file(CLIENT_KEYS_PATH)
    control_service('start')


def create_force_config_block(param, config_path):
    """
    Creates a temporal config file.
    """
    temp = os.path.join(os.path.dirname(config_path), 'temp.yaml')

    with open(config_path, 'r') as conf_file:
        temp_conf_file = yaml.safe_load(conf_file)
        for elem in param:
            temp_conf_file[0]['sections'][0]['elements'].append(elem)
    with open(temp, 'w') as temp_file:
        yaml.safe_dump(temp_conf_file, temp_file)
    return temp


@pytest.fixture(scope='function')
def format_configuration(get_current_test_case, request):
    """
    Get configuration block from current test case
    """
    test_name = request.node.originalname
    configuration = get_current_test_case.get('configuration', {})

    # Configuration for testing
    temp = create_force_config_block(configuration, request.module.configurations_path)
    conf = load_wazuh_configurations(temp, test_name)
    os.remove(temp)

    test_config = set_section_wazuh_conf(conf[0]['sections'])

    return test_config


@pytest.fixture(scope='function')
def override_authd_force_conf(format_configuration):
    """
    Re-writes Wazuh configuration file with new configurations from the test case.
    """
    # Save current configuration
    backup_config = get_wazuh_conf()

    # Set new configuration
    write_wazuh_conf(format_configuration)

    yield

    # Restore previous configuration
    write_wazuh_conf(backup_config)


@pytest.fixture(scope='module')
def get_api_details():
    return get_api_details_dict


@pytest.fixture(scope='module')
def restart_api_module():
    # Stop Wazuh and Wazuh API
    control_service('stop')
    truncate_file(API_LOG_FILE_PATH)
    control_service('start')


@pytest.fixture(scope='module')
def wait_for_start_module():
    # Wait for API to start
    file_monitor = FileMonitor(API_LOG_FILE_PATH)
    file_monitor.start(timeout=20, callback=callback_detect_api_start,
                       error_message='Did not receive expected "INFO: Listening on ..." event')

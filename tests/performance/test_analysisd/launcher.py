import argparse
import sys
import os
from tempfile import gettempdir

from wazuh_testing.qa_ctl.provisioning import local_actions
from wazuh_testing.tools import github_checks
from wazuh_testing.tools.github_api_requests import WAZUH_QA_REPO
from wazuh_testing.tools.exceptions import QAValueError
from wazuh_testing.tools.logging import Logging
from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.qa_ctl.configuration.config_generator import QACTLConfigGenerator
from wazuh_testing.tools.s3_package import get_last_production_package_url, get_production_package_url
from wazuh_testing.tools.time import get_current_timestamp

TMP_FILES = os.path.join(gettempdir(), 'wazuh_analysisd_ingestion_avg')
WAZUH_QA_FILES = os.path.join(TMP_FILES, 'wazuh-qa')
ANALYSISD_INGESTION_AVG_TEST_PATH = os.path.join(WAZUH_QA_FILES, 'tests', 'performance', 'test_analysisd')

logger = Logging(QACTL_LOGGER)
test_build_files = []


def get_parameters():
    """
    Returns:
        argparse.Namespace: Object with the user parameters.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('--os', '-o', type=str, action='store', required=False, dest='os_system',
                        choices=['centos_7', 'centos_8', 'ubuntu'], default='ubuntu')

    parser.add_argument('--version', '-v', type=str, action='store', required=False, dest='wazuh_version',
                        help='Wazuh installation and tests version.')

    parser.add_argument('--debug', '-d', action='count', default=0, help='Run in debug mode. You can increase the debug'
                                                                         ' level with more [-d+]')

    parser.add_argument('--persistent', '-p', action='store_true',
                        help='Persistent instance mode. Do not destroy the instances once the process has finished.')

    parser.add_argument('--qa-branch', type=str, action='store', required=False, dest='qa_branch', default='master',
                        help='Set a custom wazuh-qa branch to download and run the tests files')

    parser.add_argument('--no-validation', action='store_true', help='Disable the script parameters validation.')

    arguments = parser.parse_args()

    return arguments

def set_environment(parameters):
    """Prepare the local environment for the test run.

    Args:
        parameters (argparse.Namespace): Object with the user parameters.

    """
    set_logger(parameters)

    # Download wazuh-qa repository to launch the check-files test files.
    local_actions.download_local_wazuh_qa_repository(branch=parameters.qa_branch, path=TMP_FILES)
    test_build_files.append(WAZUH_QA_FILES)

def set_logger(parameters):
    """Set the test logging.

    Args:
        parameters (argparse.Namespace): Object with the user parameters.
    """
    level = 'DEBUG' if parameters.debug >= 1 else 'INFO'
    logger.set_level(level)

    # Disable traceback if it is not run in DEBUG mode
    if level != 'DEBUG':
        sys.tracebacklimit = 0

def validate_parameters(parameters):
    """Validate input script parameters.

    Raises:
        QAValueError: If a script parameters has a invalid value.
    """
    logger.info('Validating input parameters')

    # Check if QA branch exists
    if not github_checks.branch_exists(parameters.qa_branch, repository=WAZUH_QA_REPO):
        raise QAValueError(f"{parameters.qa_branch} branch does not exist in Wazuh QA repository.",
                           logger.error, QACTL_LOGGER)

    # Check version parameter
    if parameters.wazuh_version and len((parameters.wazuh_version).split('.')) != 3:
        raise QAValueError(f"Version parameter has to be in format x.y.z. You entered {parameters.wazuh_version}",
                           logger.error, QACTL_LOGGER)

    # Check if Wazuh has the specified version
    if parameters.wazuh_version and not github_checks.version_is_released(parameters.wazuh_version):
        raise QAValueError(f"The wazuh {parameters.wazuh_version} version has not been released. Enter a right "
                           'version.', logger.error, QACTL_LOGGER)
    logger.info('Input parameters validation has passed successfully')


def main():
    parameters = get_parameters()

    # Set logging and Download QA files
    set_environment(parameters)

    # Validate script parameters
    if not parameters.no_validation:
        validate_parameters(parameters)


if __name__ == '__main__':
    main()
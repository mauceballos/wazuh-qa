import argparse
import sys
import os
from tempfile import gettempdir

from wazuh_testing.qa_ctl.provisioning import local_actions
from wazuh_testing.qa_ctl.provisioning.ansible import playbook_generator
from wazuh_testing.tools import github_checks
from wazuh_testing.tools.github_api_requests import WAZUH_QA_REPO
from wazuh_testing.tools.exceptions import QAValueError
from wazuh_testing.tools.logging import Logging
from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.qa_ctl.configuration.config_instance import ConfigInstance
from wazuh_testing.qa_ctl.configuration.config_generator import QACTLConfigGenerator
from wazuh_testing.tools import file
from wazuh_testing.tools.s3_package import get_last_production_package_url, get_production_package_url
from wazuh_testing.tools.time import get_current_timestamp

TMP_FILES = os.path.join(gettempdir(), 'wazuh_analysisd_ingestion_avg')
WAZUH_QA_FILES = os.path.join(TMP_FILES, 'wazuh-qa')
ANALYSISD_INGESTION_AVG_TEST_PATH = os.path.join(
    WAZUH_QA_FILES, 'tests', 'performance', 'test_analysisd', 'test_analysisd_ingestion_rate'
)

logger = Logging(QACTL_LOGGER)
test_build_files = []


def get_parameters():
    """
    Returns:
        argparse.Namespace: Object with the user parameters.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('--os', '-o', type=str, action='store', required=False,
                        dest='os_system',
                        choices=['centos_7', 'centos_8', 'ubuntu'],
                        default='ubuntu')

    parser.add_argument('--initial-version', '-i', type=str, action='store',
                        required=True, dest='from_version',
                        help='Wazuh installation and tests version.')

    parser.add_argument('--target-version', '-v', type=str, action='store',
                        required=True, dest='target_version',
                        help='Target version to upgrade Wazuh to.')

    parser.add_argument('--stress-time', '-t', type=int, action='store',
                        required=False, dest='stress_time', default=60,
                        help="Time in seconds to stress Analysisd")

    parser.add_argument('--ingestion-rate', '-r', type=int, action='store',
                        required=True, dest='ingestion_rate',
                        help="EPS ingestion rate")

    parser.add_argument("--queue-size", "-s", type=int, required=False,
                        default=16384, dest='queue_size',
                        help="Size of Analysisd`s 'decode event' queue")

    parser.add_argument('--debug', '-d', action='count', default=0,
                        help='Run in debug mode. You can increase the debug'
                        ' level with more [-d+]')

    parser.add_argument('--persistent', '-p', action='store_true',
                        help='Persistent instance mode. Do not destroy the '
                        'instances once the process has finished.')

    parser.add_argument('--qa-branch', type=str, action='store',
                        required=False, dest='qa_branch', default='master',
                        help='Set a custom wazuh-qa branch to download '
                        'and run the tests')

    parser.add_argument('--no-validation', action='store_true',
                        help='Disable the script parameters validation.')

    arguments = parser.parse_args()

    return arguments


def set_environment(parameters):
    """Prepare the local environment for the test run.

    Args:
        parameters (argparse.Namespace): Object with the user parameters.

    """
    set_logger(parameters)

    # Download wazuh-qa repository
    local_actions.download_local_wazuh_qa_repository(
        branch=parameters.qa_branch, path=TMP_FILES
    )
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
    if not github_checks.branch_exists(parameters.qa_branch,
                                       repository=WAZUH_QA_REPO):
        raise QAValueError(f"{parameters.qa_branch} branch does not exist in "
                           "Wazuh QA repository.",
                           logger.error, QACTL_LOGGER)

    # Check version parameter
    initial_v = [int(_) for _ in (parameters.from_version).split('.')]
    target_v = [int(_) for _ in (parameters.target_version).split('.')]
    error_flag = False
    if initial_v[0] > target_v[0]:
        error_flag = True
    elif initial_v[0] == target_v[0] and initial_v[1] > target_v[1]:
        error_flag = True
    elif initial_v[0] == target_v[0] and initial_v[1] == target_v[1] \
            and initial_v[2] > target_v[2]:
        error_flag = True

    if error_flag:
        raise QAValueError(f"Initial version must be minor than the target version."
                           f"Initial version: {parameters.from_version} "
                           f"Target version: {parameters.target_version}",
                           logger.error, QACTL_LOGGER)
    versions = [parameters.from_version, parameters.target_version]
    for version in versions:
        if version and len(version) != 5:
            raise QAValueError(f"Version parameter has to be in format x.y.z. "
                               f"You entered {version}",
                               logger.error, QACTL_LOGGER)
        # Check if Wazuh has the specified version
        if not github_checks.version_is_released(version):
            raise QAValueError(f"The wazuh {version} version has "
                               "not been released. Enter a right version.",
                               logger.error, QACTL_LOGGER)
    logger.info('Input parameters validation has passed successfully')


def generate_test_playbooks(parameters, local_pre_data_path,
                            local_post_data_path):
    """Generate the necessary playbooks to run the test.

    Args:
        parameters (argparse.Namespace): Object with the user parameters.
        local_pre_data_path (str): Local path where the stress data
        will be saved.
        local_post_data_path (str): Local path where the stress data
        will be saved.
    """
    playbooks_path = []
    initial_package_url = get_production_package_url('manager',
                                                     parameters.os_system,
                                                     parameters.from_version)
    target_package_url = get_production_package_url('manager',
                                                    parameters.os_system,
                                                    parameters.target_version)
    initial_package_name = os.path.split(initial_package_url)[1]
    target_package_name = os.path.split(target_package_url)[1]

    stress_script_url = f"https://raw.githubusercontent.com/wazuh/wazuh-qa/" \
                        f"{parameters.qa_branch}/deps/wazuh_testing" \
                        "/wazuh_testing/scripts/stress_analysisd.py"
    os_platform = 'linux'
    package_destination = '/tmp'
    stress_script_destination = '/bin/stress_analysisd.py'
    debug_param = ''.join(' -d' if _ == 0 else 'd'
                          for _ in range(parameters.debug))
    queue_size_param = f' -s {parameters.queue_size}' \
                       if parameters.queue_size else ''
    pre_stress_data_output_path = '/pre_stress_data.json'
    post_stress_data_output_path = '/post_stress_data.json'
    pre_script_command = f"python3 {stress_script_destination} " \
                         f"-t {parameters.stress_time} " \
                         f"-e {parameters.ingestion_rate} " \
                         f"-o {pre_stress_data_output_path}" \
                         f"{debug_param}{queue_size_param}"
    post_script_command = f"python3 {stress_script_destination} " \
                          f"-t {parameters.stress_time} " \
                          f"-e {parameters.ingestion_rate} " \
                          f"-o {post_stress_data_output_path}" \
                          f"{debug_param}{queue_size_param}"

    # Playbook parameters
    download_files = {
        'files_data': {stress_script_url: stress_script_destination},
        'playbook_parameters': {'become': True}
    }

    run_pre_script_command = {'commands': [pre_script_command],
                              'playbook_parameters': {'become': True}}

    run_post_script_command = {'commands': [post_script_command],
                               'playbook_parameters': {'become': True}}

    fetch_files_playbook_parameters = {
        'files_data': {
            post_stress_data_output_path: local_post_data_path,
            pre_stress_data_output_path: local_pre_data_path
        },
        'playbook_parameters': {'become': True}
    }

    install_wazuh_playbook_parameters = {
        'wazuh_target': 'manager',
        'package_name': initial_package_name,
        'package_url': initial_package_url,
        'package_destination': package_destination,
        'os_system': parameters.os_system, 'os_platform': os_platform
    }
    upgrade_wazuh_playbook_parameters = {
        'package_name': target_package_name,
        'package_url': target_package_url,
        'package_destination': package_destination,
        'os_system': parameters.os_system, 'os_platform': os_platform
    }

    # Playbooks builder section

    # Add playbook for downloading the stress script in the remote host
    playbooks_path.append(playbook_generator.download_files(**download_files))
    # Add playbook for running pre-stress script
    playbooks_path.append(playbook_generator.install_wazuh(**install_wazuh_playbook_parameters))
    playbooks_path.append(playbook_generator.run_linux_commands(**run_pre_script_command))
    playbooks_path.append(playbook_generator.upgrade_wazuh(**upgrade_wazuh_playbook_parameters))

    # Add playbook for running the post-stress script
    playbooks_path.append(playbook_generator.run_linux_commands(**run_post_script_command))
    # Add playbook for fetching the stress data
    playbooks_path.append(playbook_generator.fetch_files(**fetch_files_playbook_parameters))

    return playbooks_path


def generate_qa_ctl_configuration(parameters, playbooks_path, qa_ctl_config_generator):
    """Generate the qa-ctl configuration according to the script parameters and write it into a file.

    Args:
        parameters (argparse.Namespace): Object with the user parameters.
        playbook_path (list(str)): List with the playbooks path to run with qa-ctl
        qa_ctl_config_generator (QACTLConfigGenerator): qa-ctl config generator object.

    Returns:
        str: Configuration file path where the qa-ctl configuration has been saved.
    """

    logger.info('Generating qa-ctl configuration')

    current_timestamp = str(get_current_timestamp()).replace('.', '_')
    config_file_path = os.path.join(TMP_FILES, f"stress_analysisd_config_{current_timestamp}.yaml")
    os_system = parameters.os_system

    instance_name = f"stress_analysisd_{os_system}_{current_timestamp}"
    instance = ConfigInstance(instance_name, os_system)

    # Generate deployment configuration
    deployment_configuration = qa_ctl_config_generator.get_deployment_configuration([instance])

    # Generate tasks configuration data
    tasks_configuration = qa_ctl_config_generator.get_tasks_configuration([instance], playbooks_path)

    # Generate qa-ctl configuration file
    qa_ctl_configuration = {**deployment_configuration, **tasks_configuration}
    file.write_yaml_file(config_file_path, qa_ctl_configuration)
    test_build_files.append(config_file_path)

    logger.info(f"The qa-ctl configuration has been created successfully in {config_file_path}")

    return config_file_path


def main():
    parameters = get_parameters()
    try:
        # Validate script parameters
        if not parameters.no_validation:
            validate_parameters(parameters)

        # Set logging and Download QA files
        set_environment(parameters)

        qa_ctl_config_generator = QACTLConfigGenerator()
        current_timestamp = str(get_current_timestamp()).replace('.', '_')
        pre_stress_data_path = os.path.join(TMP_FILES, f"pre_stress_data_{current_timestamp}.yaml")
        post_stress_data_path = os.path.join(TMP_FILES, f"post_stress_data_{current_timestamp}.yaml")
        # Generate the test playbooks to run with qa-ctl
        playbooks_path = generate_test_playbooks(
            parameters, pre_stress_data_path, post_stress_data_path)
        test_build_files.extend(playbooks_path)
        # Generate the qa-ctl configuration
        qa_ctl_config_file_path = generate_qa_ctl_configuration(
            parameters, playbooks_path, qa_ctl_config_generator
        )
        # Run the qa-ctl with the generated configuration.
        # Launch deployment + custom playbooks.
        qa_ctl_extra_args = ''.join(' -d' if _ == 0 else 'd'
                                    for _ in range(parameters.debug))
        qa_ctl_extra_args += ' -p' if parameters.persistent else ''

        local_actions.run_local_command_printing_output(
            f"qa-ctl -c {qa_ctl_config_file_path} {qa_ctl_extra_args} "
            '--no-validation-logging'
        )

        # Check that the post-stress data has been fetched correctly
        if os.path.exists(post_stress_data_path):
            test_build_files.append(post_stress_data_path)
            logger.info(f"The post-stress data has been saved in {post_stress_data_path}")
        else:
            raise QAValueError(f"Could not find the post-stress data in {TMP_FILES} path", logger.error,
                               QACTL_LOGGER)
        # Check that the post-stress data has been fetched correctly
        if os.path.exists(pre_stress_data_path):
            test_build_files.append(pre_stress_data_path)
            logger.info(f"The pre-stress data has been saved in {pre_stress_data_path}")
        else:
            raise QAValueError(f"Could not find the pre-stress data in {TMP_FILES} path", logger.error,
                               QACTL_LOGGER)
        # Launch the stress analysisd test
        pytest_launcher = 'python -m pytest' if sys.platform == 'win32' \
                          else 'python3 -m pytest'
        pytest_command = f"cd {ANALYSISD_INGESTION_AVG_TEST_PATH} && " \
                         f"{pytest_launcher} test_analysisd_ingestion_avg " \
                         f"--before-results {pre_stress_data_path} " \
                         f"--after-results {post_stress_data_path} " \
                         f"--output-path {TMP_FILES} " \
                         f"--ingestion-rate {parameters.ingestion_rate}"
        test_result = local_actions.run_local_command_returning_output(
            pytest_command
        )
        print(test_result)
    finally:
        # Clean test build files
        if parameters and not parameters.persistent:
            logger.info('Deleting all test artifacts files of this build.')
            for file_to_remove in test_build_files:
                file.remove_file(file_to_remove)


if __name__ == '__main__':
    main()

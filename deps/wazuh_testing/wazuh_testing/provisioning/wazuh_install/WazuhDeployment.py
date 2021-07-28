
from abc import ABC, abstractmethod
from wazuh_testing.provisioning.ansible.AnsibleTask import AnsibleTask
from wazuh_testing.provisioning.ansible.AnsibleRunner import AnsibleRunner


class WazuhDeployment(ABC):
    """Deploy Wazuh with all the elements needed, set from the configuration file

    Args:
        installation_files (string): Path where is located the Wazuh instalation files.
        configuration (WazuhConfiguration): Configuration object to be set.
        inventory_file_path (string): Path where is located the ansible inventory file.
        install_mode (string): 'package' or 'sources' installation mode.
        install_dir_path (string): Path where the Wazuh installation will be stored.
        hosts (string): Group of hosts to be deployed.

    Attributes:
        installation_files (string): Path where is located the Wazuh instalation files.
        configuration (WazuhConfiguration): Configuration object to be set.
        inventory_file_path (string): Path where is located the ansible inventory file.
        install_mode (string): 'package' or 'sources' installation mode.
        install_dir_path (string): Path where the Wazuh installation will be stored.
        hosts (string): Group of hosts to be deployed.
    """
    def __init__(self, installation_files, configuration=None, inventory_file_path='/tmp/inventory.yaml',
                 install_mode='package', install_dir_path='/var/ossec', hosts='all', ip_server=None):
        self.installation_files = installation_files
        self.configuration = configuration
        self.inventory_file_path = inventory_file_path
        self.install_mode = install_mode
        self.install_dir_path = install_dir_path
        self.hosts = hosts
        self.ip_server = ip_server

    @abstractmethod
    def install(self, install_type):
        """Installs Wazuh (agent or manager) by creating an ansible playbook and launching it

        Returns:
            AnsibleOutput: Result of the ansible playbook run.
        """
        tasks_list = []
        if self.install_mode == 'sources':
            tasks_list.append(AnsibleTask({
                    'name': 'Install dependencies to build Wazuh packages',
                    'package': {'name': ['make', 'gcc', 'automake', 'autoconf', 'libtool',
                                         'tar', 'libc6-dev', 'curl', 'policycoreutils'],
                                'state': 'present'}}))

            tasks_list.append(AnsibleTask({
                'name': 'Clean remaining files from others builds',
                'command': 'make -C src {{ item }}',
                'args': {'chdir': f'{self.installation_files}'},
                'with_items': ['clean', 'clean-deps'],
                'when': 'ansible_system == "Linux"'}))

            tasks_list.append(AnsibleTask({
                'name': 'Render the "preloaded-vars.conf" file',
                'template': {'src': '/home/vhalgarv/drawers/git/wazuh-qa/deps/wazuh_testing/wazuh_testing/provisioning/wazuh_install/templates/preloaded_vars.conf.j2',
                             'dest': f'{self.installation_files}/etc/preloaded-vars.conf',
                             'owner': 'root',
                             'group': 'root',
                             'mode': '0644'},
                'vars': {'install_type': install_type,
                         'install_dir': f'{self.install_dir_path}',
                         'ip_server': f'{self.ip_server}',
                         'ca_store': f'{self.installation_files}/wpk_root.pem',
                         'make_cert': 'y' if install_type == 'server' else 'n'},
                'when': 'ansible_system == "Linux"'}))

            tasks_list.append(AnsibleTask({
                'name': 'Executing "install.sh" script to build and install Wazuh',
                'shell': './install.sh > /tmp/wazuh_install_log.txt',
                'args': {'chdir': f'{self.installation_files}'},
                'when': 'ansible_system == "Linux"'}))

        elif self.install_mode == 'package':
            tasks_list.append(AnsibleTask({'name': 'Install Wazuh Agent from .deb packages',
                                           'apt': {'deb': f'{self.installation_files}'},
                                           'when': 'ansible_os_family|lower == "debian"'}))

            tasks_list.append(AnsibleTask({'name': 'Install Wazuh Agent from .rpm packages | yum',
                                           'yum': {'name': f'{self.installation_files}'},
                                           'when': ['ansible_os_family|lower == "redhat"',
                                                    'not (ansible_distribution|lower == "centos" and ' +
                                                    'ansible_distribution_major_version >= "8")',
                                                    'not (ansible_distribution|lower == "redhat" and ' +
                                                    'ansible_distribution_major_version >= "8")']}))

            tasks_list.append(AnsibleTask({'name': 'Install Wazuh Agent from .rpm packages | dnf',
                                           'dnf': {'name': f'{self.installation_files}'},
                                           'when': ['ansible_os_family|lower == "redhat"',
                                                    '(ansible_distribution|lower == "centos" and ' +
                                                    'ansible_distribution_major_version >= "8") or' +
                                                    '(ansible_distribution|lower == "redhat" and ' +
                                                    'ansible_distribution_major_version >= "8")']}))

            tasks_list.append(AnsibleTask({'name': 'Install Wazuh Agent from Windows packages',
                                           'win_package': {'path': f'{self.installation_files}'},
                                           'when': 'ansible_system == "Windows"'}))

            tasks_list.append(AnsibleTask({'name': 'Install macOS wazuh package',
                                           'shell': 'installer -pkg wazuh-* -target /',
                                           'args': {'chdir': f'{self.installation_files}'},
                                           'when': 'ansible_system == "Darwin"'}))

        playbook_parameters = {'tasks_list': tasks_list, 'hosts': self.hosts, 'gather_facts': True, 'become': True}

        return AnsibleRunner.run_ephemeral_tasks(self.inventory_file_path, playbook_parameters)

    def __control_service(self, command, install_type):
        """Private method to control the Wazuh service in different systems.

        Returns:
            AnsibleOutput: Result of the ansible playbook run.
        """
        tasks_list = []
        service_name = install_type if install_type == 'agent' else 'manager'
        service_command = f'{command}ed' if command != 'stop' else 'stopped'

        tasks_list.append(AnsibleTask({'name': f'Wazuh manager {command} service',
                                       'become': True,
                                       'systemd': {'name': f'wazuh-{service_name}',
                                                   'state': f'{service_command}'},
                                       'register': 'output_command',
                                       'ignore_errors': 'true',
                                       'when': 'ansible_system == "Linux"'}))

        tasks_list.append(AnsibleTask({'name': f'Wazuh agent {command} service',
                                       'become': True,
                                       'command': f'{self.install_dir_path}/bin/wazuh-control {command}',
                                       'when': 'ansible_system == "darwin" or ansible_system == "SunOS" or ' +
                                               'output_command.failed == true'}))

        tasks_list.append(AnsibleTask({'name': f'Wazuh agent {command} service',
                                       'win_shell': 'Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue |' +
                                                    f' {command.capitalize()}-Service -ErrorAction SilentlyContinue',
                                       'args': {'executable': 'powershell.exe'},
                                       'when': 'ansible_system == "Windows"'}))

        playbook_parameters = {'tasks_list': tasks_list, 'hosts': self.hosts, 'gather_facts': True, 'become': True}

        return AnsibleRunner.run_ephemeral_tasks(self.inventory_file_path, playbook_parameters)

    @abstractmethod
    def start_service(self, install_type):
        """Abstract method to start service

        Returns:
            AnsibleOutput: Result of the ansible playbook run.
        """
        self.__control_service('start', install_type)

    @abstractmethod
    def restart_service(self, install_type):
        """Abstract method to restart service

        Returns:
            AnsibleOutput: Result of the ansible playbook run.
        """
        self.__control_service('restart', install_type)

    @abstractmethod
    def stop_service(self, install_type):
        """Abstract method to stop service

        Returns:
            AnsibleOutput: Result of the ansible playbook run.
        """
        self.__control_service('stop', install_type)

    @abstractmethod
    def health_check(self):
        """Check if the installation is full complete, and the necessary items are ready

        Returns:
            AnsibleOutput: Result of the ansible playbook run.
        """
        tasks_list = []
        tasks_list.append(AnsibleTask({'name': 'Read ossec.log searching errors',
                                       'lineinfile': {'path': f'{self.install_dir_path}/logs/ossec.log',
                                                      'line': 'ERROR|CRITICAL'},
                                       'when': 'ansible_system != "Windows"',
                                       'register': 'exists',
                                       'check_mode': 'yes',
                                       'failed_when': 'exists is not changed'}))

        tasks_list.append(AnsibleTask({'name': 'Read ossec.log searching errors',
                                       'lineinfile': {'path': f'{self.install_dir_path}/ossec.log',
                                                      'line': 'ERROR'},
                                       'when': 'ansible_system == "Windows"',
                                       'register': 'exists',
                                       'check_mode': 'yes',
                                       'failed_when': 'exists is not changed'}))

        playbook_parameters = {'tasks_list': tasks_list, 'hosts': self.hosts, 'gather_facts': True, 'become': True}

        return AnsibleRunner.run_ephemeral_tasks(self.inventory_file_path, playbook_parameters)

    def wazuh_is_already_installed(self):
        """Check if Wazuh is installed in the system

        Returns:
            bool: True if wazuh is already installed, False if not
        """
        tasks_list = []
        tasks_list.append(AnsibleTask({'name': 'Check Wazuh directory exist',
                                       'stat': {'path': f'{self.install_dir_path}'},
                                       'register': 'dir_exist',
                                       'failed_when': 'dir_exist.stat.exists and dir_exist.stat.isdir'}))

        playbook_parameters = {'tasks_list': tasks_list, 'hosts': self.hosts, 'gather_facts': True, 'become': True}

        output = AnsibleRunner.run_ephemeral_tasks(self.inventory_file_path, playbook_parameters, raise_on_error=False)

        if output.rc == 0:
            return False
        else:
            return True

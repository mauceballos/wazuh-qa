# Wazuh

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://wazuh.com/community/join-us-on-slack/)
[![Email](https://img.shields.io/badge/email-join-blue.svg)](https://groups.google.com/forum/#!forum/wazuh)
[![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://documentation.wazuh.com)
[![Documentation](https://img.shields.io/badge/web-view-green.svg)](https://wazuh.com)
[![Twitter](https://img.shields.io/twitter/follow/wazuh?style=social)](https://twitter.com/wazuh)
[![YouTube](https://img.shields.io/youtube/views/peTSzcAueEc?style=social)](https://www.youtube.com/watch?v=peTSzcAueEc)


Wazuh is a free and open source platform used for threat prevention, detection, and response. It is capable of protecting workloads across on-premises, virtualized, containerized, and cloud-based environments.

Wazuh solution consists of an endpoint security agent, deployed to the monitored systems, and a management server, which collects and analyzes data gathered by the agents. Besides, Wazuh has been fully integrated with the Elastic Stack, providing a search engine and data visualization tool that allows users to navigate through their security alerts.

## Wazuh QA repository

In this repository you will find the tests used in the CI environment to test Wazuh's capabilities and daemons. This is the structure of the repository:

- **[deps](deps/)**:  contains a Python's framework used to automatize tasks and interact with Wazuh.
- **[tests](tests/)**: directory containing the test suite. These are tests developed using Pytest.
    - **[integration](tests/integration/)**: integration tests for the different daemons/components.
    - **[system](tests/system)**: system tests.
    - **[scans](tests/scans)**: tests to validate the output of running static code and dependencies scanners looking for flaws and vulnerabilities
- **[docs](link/to/docs)**: contains the technical documentation about the code and documentation about the tests.

## Builds docs locally

To build Wazuh QA documentation simply clone this repository and run `/provision_documentation.sh` script on `docs` folder.

The docs should be available on localhost: `http://localhost:8080`

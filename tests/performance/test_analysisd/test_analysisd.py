import os
import shutil as sh
import pytest
import yaml
import socket
from sys import path
from threading import Thread
import wazuh_testing.tools as tools
from wazuh_testing.tools.performance.binary import Monitor
from deps.wazuh_testing.wazuh_testing.tools import ANALYSISD_QUEUE_SOCKET_PATH

#Config
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_results_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'results')
ingestion_rates_path = os.path.join(test_data_path, 'analysisd_logs.yaml')
with open(ingestion_rates_path) as test_cases_file:
    test_cases = yaml.safe_load(test_cases_file)

#Test
@pytest.mark.parametrize('test_cases',
                         [test_case['test_case'] for test_case in test_cases],
                         ids=[test_case['name'] for test_case in test_cases])
def test_analysisd(test_cases):
    for scenario in test_cases:
        # Creating a path for results
        if os.path.exists(f"{test_results_path}/{scenario['eps']}"):
            sh.rmtree(f"{test_results_path}/{scenario['eps']}", ignore_errors=True)
        os.mkdir(f"{test_results_path}/{scenario['eps']}")
        monitor = Monitor(process_name='analysisd', dst_dir=f'{test_results_path}/{scenario["eps"]}')
        
        msg = '0912:tmpdir:Mensaje'
        
        def send_message(message, wazuh_socket):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.connect(wazuh_socket)
            sock.send(message.encode())
            sock.close()

        threads = []

        for i in range(0, scenario['eps']):
            threads.append(Thread(target=send_message, args=(msg, ANALYSISD_QUEUE_SOCKET_PATH)))

        monitor.start()

       	for thread in threads:
            thread.start()
        
        for thread in threads:
            thread.join()

        monitor.shutdown()

        file.truncate_file(tools.ARCHIVES_LOG_FILE_PATH)
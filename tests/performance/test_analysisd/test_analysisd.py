import os
import shutil as sh
import pytest
import yaml
import socket
from sys import path
from wazuh_testing.tools.thread_executor import ThreadExecutor
import wazuh_testing.tools as tools
from wazuh_testing.tools import file
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
        msg = '0912:tmpdir:Mensaje'
        if os.path.exists(f"{test_results_path}/{scenario['eps']}"):
            sh.rmtree(f"{test_results_path}/{scenario['eps']}", ignore_errors=True)
            os.mkdir(f"{test_results_path}/{scenario['eps']}")
        monitor = Monitor(process_name='analysisd', dst_dir=f'{test_results_path}/{scenario["eps"]}')
        def send_message(message, wazuh_socket):

            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.connect(wazuh_socket)
            sock.send(message.encode())
            sock.close()

        events_threads = []

        monitor.start()

        for event in range(0, scenario['eps']):
            events_threads.append(ThreadExecutor(send_message, {'message': msg, 'wazuh_socket': ANALYSISD_QUEUE_SOCKET_PATH}))

       	for thread in events_threads:
            thread.start()
        
        for thread in events_threads:
            thread.join()

        monitor.shutdown()

        file.truncate_file(tools.ARCHIVES_LOG_FILE_PATH)

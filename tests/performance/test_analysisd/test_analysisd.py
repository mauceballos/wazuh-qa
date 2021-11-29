import os
import pytest
import yaml
import socket
from sys import path
from deps.wazuh_testing.wazuh_testing.tools import ANALYSISD_QUEUE_SOCKET_PATH

#Config
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
ingestion_rates_path = os.path.join(test_data_path, 'analysisd_logs.yaml')
with open(ingestion_rates_path) as test_cases_file:
    test_cases = yaml.safe_load(test_cases_file)

#Test
@pytest.mark.parametrize('test_cases',
                         [test_case['test_case'] for test_case in test_cases],
                         ids=[test_case['name'] for test_case in test_cases])
def test_analysisd(test_cases):
    for scenario in test_cases:
        msg = scenario['id'] + ':' + scenario['location'] + ':' + scenario['log']
        
        def send_message(message, wazuh_socket):

            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.connect(wazuh_socket)
            sock.send(message.encode())
            sock.close()

          
        send_message(message=msg, wazuh_socket=ANALYSISD_QUEUE_SOCKET_PATH)



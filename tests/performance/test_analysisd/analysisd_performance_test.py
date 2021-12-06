import pytest
import time
import os
import yaml
import sys
from injector import Injector

print(sys.path)

#Config
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
ingestion_rates_path = os.path.join(test_data_path, 'analysisd_logs.yaml')
with open(ingestion_rates_path) as test_cases_file:
    test_cases = yaml.safe_load(test_cases_file)
local_internal_options = {'analysisd.decode_event_queue_size': '500'}

#Test
@pytest.mark.parametrize('test_cases',
                         [test_case['test_case'] for test_case in test_cases],
                         ids=[test_case['name'] for test_case in test_cases])
def test_analysisd(test_cases):
    for scenario in test_cases:
        decoded_data_set, dropped_data_set = Injector(scenario['eps'], 60)
        eps_decoded_avg = 0
        events_dropped_avg = 0
        for events in decoded_data_set:
            eps_decoded_avg += int(events)
        for events_dropped in dropped_data_set:
            events_dropped_avg += int(events_dropped)

        eps_decoded_avg = eps_decoded_avg / len(decoded_data_set)
        events_dropped_avg = events_dropped_avg / len(dropped_data_set)
        print(f'Decoded Average: {eps_decoded_avg} ----- Dropped Average: {events_dropped_avg}', end='\n')

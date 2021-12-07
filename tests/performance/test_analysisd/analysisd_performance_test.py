import pytest
import time
import os
import yaml
import sys
from injector import Injector
from wazuh_testing.tools import file, ARCHIVES_LOG_FILE_PATH, WAZUH_LOCAL_INTERNAL_OPTIONS
from wazuh_testing.tools.configuration import get_local_internal_options_dict, set_local_internal_options_dict


#Config
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
ingestion_rates_path = os.path.join(test_data_path, 'analysisd_logs.yaml')
with open(ingestion_rates_path) as test_cases_file:
    test_cases = yaml.safe_load(test_cases_file)
# Decrease the queue size
options = {'analysisd.decode_event_queue_size': '500'}
backup_local_internal_opt = get_local_internal_options_dict()
set_local_internal_options_dict(options)
local_internal_opt_file = get_local_internal_options_dict()


#Test
@pytest.mark.parametrize('test_cases',
                         [test_case['test_case'] for test_case in test_cases],
                         ids=[test_case['name'] for test_case in test_cases])
def test_analysisd(test_cases):
    for scenario in test_cases:
        eps_decoded_avg = 0
        events_dropped_avg = 0
        injector = Injector(scenario['eps'], 60)

        decoded_data_set, dropped_data_set = injector.start_injector()

        if len(decoded_data_set) > 0:
            for events in decoded_data_set:
                eps_decoded_avg += int(events)
            eps_decoded_avg = eps_decoded_avg / len(decoded_data_set)
        if len(dropped_data_set) > 0:
            for events_dropped in dropped_data_set:
                events_dropped_avg += int(events_dropped)
            events_dropped_avg = events_dropped_avg / len(dropped_data_set)

        print(f'--Decoded Average: {round(eps_decoded_avg,2)}\n--Dropped Average: {round(events_dropped_avg,2)}\n')
        file.truncate_file(ARCHIVES_LOG_FILE_PATH)
    set_local_internal_options_dict(backup_local_internal_opt) # Restore local internal options

import pytest
import os
import yaml
import json
from injector import Injector
from wazuh_testing.tools import file, ARCHIVES_LOG_FILE_PATH
from wazuh_testing.tools import WAZUH_LOCAL_INTERNAL_OPTIONS
from wazuh_testing.tools.configuration import get_local_internal_options_dict
from wazuh_testing.tools.configuration import set_local_internal_options_dict


# Config
test_data_path = os.path.join(os.path.dirname(
        os.path.realpath(__file__)), 'data'
    )
ingestion_rates_path = os.path.join(test_data_path, 'analysisd_logs.yaml')
with open(ingestion_rates_path) as test_cases_file:
    test_cases = yaml.safe_load(test_cases_file)


# Test
@pytest.mark.parametrize('test_cases',
                         [test_case['test_case'] for test_case in test_cases],
                         ids=[test_case['name'] for test_case in test_cases])
def test_analysisd(test_cases):
    results = {}
    for scenario in test_cases:
        # Backup the local internal options
        backup_local_internal_opt = get_local_internal_options_dict()
        # Decrease the queue size
        queue_size = scenario["analysisd_queue_size"]
        options = {
            'analysisd.decode_event_queue_size': f'{queue_size}'
        }
        set_local_internal_options_dict(options)

        # Dict to print the results
        results[f'{scenario["eps"]}'] = {}

        # Set average to 0
        eps_decoded_avg = 0
        events_dropped_avg = 0

        # Create the injector object
        injector = Injector(scenario['eps'], scenario['execution_time'])
        # Start sending EPS to analysisd socket and
        # wait until it starts dropping
        decoded_data_set, dropped_data_set = injector.start_injector()

        # Calculate the average
        if len(decoded_data_set) > 0:
            for events in decoded_data_set:
                eps_decoded_avg += int(events)
            eps_decoded_avg = eps_decoded_avg / len(decoded_data_set)
            eps_decoded_avg = round(eps_decoded_avg, 2)
        if len(dropped_data_set) > 0:
            for events_dropped in dropped_data_set:
                events_dropped_avg += int(events_dropped)
            events_dropped_avg = events_dropped_avg / len(dropped_data_set)
            events_dropped_avg = round(events_dropped_avg, 2)

        results[f'{scenario["eps"]}']['decoded_avg'] = eps_decoded_avg
        results[f'{scenario["eps"]}']['dropped_avg'] = events_dropped_avg

        file.truncate_file(ARCHIVES_LOG_FILE_PATH)
    # Restore local internal options
    set_local_internal_options_dict(backup_local_internal_opt)
    print(json.dumps(results, sort_keys=True, indent=4))

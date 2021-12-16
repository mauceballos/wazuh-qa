import pytest
import os
import yaml


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
        pass

import os
import argparse
import socket
import time
import logging
import json
from configobj import ConfigObj
from threading import Thread
from time import sleep

from wazuh_testing.tools import ANALYSIS_STATISTICS_FILE
from wazuh_testing.tools import ANALYSISD_QUEUE_SOCKET_PATH
from wazuh_testing.tools import file, ARCHIVES_LOG_FILE_PATH
from wazuh_testing.tools.configuration import get_local_internal_options_dict
from wazuh_testing.tools.configuration import set_local_internal_options_dict

msg = '0912:tmpdir:Dec  2 16:05:37 localhost su[6625]: pam_unix(su:session): session opened for user root by vagrant(uid=0)'
script_logger = logging.getLogger('stress_manager')

statistics_file_parsed = ConfigObj(ANALYSIS_STATISTICS_FILE)

events_decoded_list = []
events_dropped_list = []
stop_threads = False
stress_time = 0

def get_parameters():
    """Process the script parameters

    Returns:
        ArgumentParser: Parameters and their values
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--stress-time", type=int, required=False, default=60, dest='stress_time',
                            help="Time in seconds to stress Analysisd")
    parser.add_argument("-e", "--number-eps", type=int, required=True, dest='number_eps',
                            help="Time in seconds to stress Analysisd")
    parser.add_argument("-s", "--queue-size", type=int, required=False, default=16384, dest='queue_size',
                            help="Size of Analysisd`s 'decode event' queue")
    parser.add_argument("-o", "--output-file", type=str, help='The path where the results are stored')
    parser.add_argument('-d', '--debug', action='store_true', help='Run in debug mode.')

    return parser.parse_args()

def configure_logger(parameters):
    """Configure the script logger

    Args:
        parameters (ArgumentParser): script parameters.
    """
    logging_level = logging.DEBUG if parameters.debug else logging.INFO
    formatter = logging.Formatter(fmt='%(asctime)s - %(levelname)s - %(message)s')

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    script_logger.setLevel(logging_level)
    script_logger.addHandler(handler)

def set_analysisd_decode_queue_size(queue_size=None):
    """Set the 'analysisd.decode_event_queue_size' option within local internal options file

    Args:
        data (dict): Check-files data
        output_file_path (string): file path to save the data
    """
    if queue_size is None:
        pass
    else:
        options = {
            'analysisd.decode_event_queue_size': f'{queue_size}'
        }
        set_local_internal_options_dict(options)

def get_analysisd_data(params):
    """Get Analysisd data through the specified stress time

    Args:
        parameters (ArgumentParser): Script parameters.
    
    Returns:
        dict: Dictionary with the analysisd results
    """
    results = {
        'EPS': params.number_eps,
        'Stress Time': params.stress_time,
        'Average': {
            'Decoded': '',
            'Dropped': ''
        } 
    }

    sum = 0
    data = [events_decoded_list, events_dropped_list]

    for _, item in enumerate(data):
        if len(item) == 0:
            results['Average'][_] = 0
        else:
            for total_events in item:
                sum += int(total_events)
            results['Average'][_] = int(sum / len(item))
    
    return results

def write_results_to_file(data, output_file_path):
    """Write the results in a file

    Args:
        data (dict): Analysisd data
        output_file_path (string): The path where the results are stored
    """
    output_dir = os.path.split(output_file_path)[0]

    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    with open(output_file_path, 'w') as file:
        file.write(json.dumps(data, indent=4))

    script_logger.info(f"The Analysisd data has been written in {output_file_path} file")

def calculate_eps_distribution(eps):
    """Calculate the EPS per thread distribution.

    Args:
        eps (int): EPS rate to be written on the socket.
    
    Returns:
        int: The number of EPS per thread
        int: The total number of threads
    """
    usable_cpus = len(os.sched_getaffinity(0))
    quantity_of_threads = (usable_cpus * 4) - 1 # 1 thread for events dropped detector
    events_per_thread = (eps + quantity_of_threads - 1) // quantity_of_threads

    return events_per_thread, quantity_of_threads

    
def create_threads(number_eps):
    """Create a list of threads depending on the number of EPS

    Args:
        number_eps (int): The number of EPS to be written on the socket.
        stress_time (int): The number of seconds to stress the daemon.
    Returns:
        list: List of threads to run.
    """
    threads = []

    distribution, quantity_of_threads = calculate_eps_distribution(number_eps)
    
    script_logger.info(f"Thread-EPS distributon = {distribution}")
    
    threads.append(Thread(target=detect_dropped_events))

    for _ in range(quantity_of_threads):
        threads.append(Thread(target=send_message, args=(distribution, msg, ANALYSISD_QUEUE_SOCKET_PATH)))
    
    return threads

def detect_dropped_events():
    script_logger.info("Start detecting dropped events")
    while True:
        global stop_threads
        if stop_threads:
            break
        events_decoded = int(statistics_file_parsed['total_events_decoded'])
        events_dropped = int(statistics_file_parsed['events_dropped'])
        if events_decoded > 0:
            events_decoded_list.append(events_decoded)
        if events_dropped > 0:
            events_dropped_list.append(events_dropped)
        script_logger.debug(f"DECODED = {events_decoded}")
        script_logger.debug(f"DROPPED = {events_dropped}")
        sleep(1)

def send_message(eps_distribution, message, wazuh_socket):
    script_logger.info("Start writing messages on Analysisd's socket")
    while True:
        global stop_threads
        if stop_threads:
            break
        start = time.perf_counter()
        for _ in range(eps_distribution):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.connect(wazuh_socket)
            sock.send(message.encode())
            sock.close()
        end = time.perf_counter()
        total = int(end - start)
        wait = 1 - total if total <= 1 else 0
        script_logger.debug(f"Waiting = {wait}")
        sleep(wait)
        global stress_time
        stress_time -= 1
        

def run_threads(threads):
    for thread in threads:
        thread.start()
    while True:
        script_logger.debug(f"STRESS TIME = {stress_time}")
        global stress_time
        if stress_time <=0:
            global stop_threads
            stop_threads = True
            break
    file.truncate_file(ARCHIVES_LOG_FILE_PATH)


def main():
    global stress_time
    args = get_parameters()
    configure_logger(args)

    backup_local_internal_opt = get_local_internal_options_dict()
    set_analysisd_decode_queue_size(args.queue_size)

    stress_time = args.stress_time

    threads = create_threads(args.number_eps)

    run_threads(threads)

    analysisd_data = get_analysisd_data(args)

    if args.output_file:
        write_results_to_file(analysisd_data, args.output_file)
    else:
        script_logger.info(json.dumps(analysisd_data, indent=4))

    set_local_internal_options_dict(backup_local_internal_opt)

if __name__ == '__main__':
    main()
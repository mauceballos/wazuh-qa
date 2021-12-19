import os
import argparse
import socket
import subprocess
import time
import logging
import json
from configobj import ConfigObj
from threading import Thread
from time import sleep

from wazuh_testing.tools import ANALYSIS_STATISTICS_FILE, WAZUH_PATH
from wazuh_testing.tools import ANALYSISD_QUEUE_SOCKET_PATH
from wazuh_testing.tools import file, ARCHIVES_LOG_FILE_PATH

msg = '0912:tmpdir:Dec  2 16:05:37 localhost su[6625]: pam_unix(su:session): '
'session opened for user root by vagrant(uid=0)'
script_logger = logging.getLogger('stress_manager')

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
    parser.add_argument("-t", "--stress-time", type=int, required=False,
                        default=60, dest='stress_time',
                        help="Time in seconds to stress Analysisd")
    parser.add_argument("-e", "--number-eps", type=int, required=True,
                        dest='number_eps',
                        help="Time in seconds to stress Analysisd")
    parser.add_argument("-s", "--queue-size", type=int, required=False,
                        default=16384, dest='queue_size',
                        help="Size of Analysisd`s 'decode event' queue")
    parser.add_argument("-o", "--output-file", type=str,
                        help='The path where the results are stored')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Run in debug mode.')

    return parser.parse_args()


def configure_logger(parameters):
    """Configure the script logger

    Args:
        parameters (ArgumentParser): script parameters.
    """
    logging_level = logging.DEBUG if parameters.debug else logging.INFO
    formatter = logging.Formatter(
        fmt='%(asctime)s - %(levelname)s - %(message)s'
    )

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    script_logger.setLevel(logging_level)
    script_logger.addHandler(handler)


def set_internal_options_conf(param=None, value=None, restore_backup=None):
    if None not in (param, value, restore_backup):
        raise ValueError("Parameters: 'param' and 'value' cannot be None if "
                         "'restore_backup' is None")

    new_content = ''
    backup = ''

    internal_options = os.path.join(WAZUH_PATH, 'etc', 'internal_options.conf')

    if restore_backup is not None:
        for line in restore_backup:
            new_content += line
    else:
        with open(internal_options, 'r') as f:
            backup = lines = f.readlines()

            for line in lines:
                new_line = line
                if param in line:
                    new_line = f'{param}={value}\n'
                new_content += new_line

    with open(internal_options, 'w') as f:
        f.write(new_content)

    script_logger.info("Restarting the manager")
    try:
        subprocess.run([f'{WAZUH_PATH}/bin/wazuh-control', 'restart'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as error:
        print(error.output)
    sleep(10)

    return backup


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

    events_sum = 0
    data = [events_decoded_list, events_dropped_list]

    for _, item in enumerate(data):
        key = list(results['Average'].keys())[_]
        if len(item) == 0:
            results['Average'][key] = 0
        else:
            for total_events in item:
                events_sum += int(total_events)
            results['Average'][key] = int(events_sum / len(item))

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

    script_logger.info(f"The Analysisd data has been written in"
                       f"{output_file_path} file")


def calculate_eps_distribution(eps):
    """Calculate the EPS per thread distribution.

    Args:
        eps (int): EPS rate to be written on the socket.

    Returns:
        int: The number of EPS per thread
        int: The total number of threads
    """
    usable_cpus = len(os.sched_getaffinity(0))
    quantity_of_threads = (usable_cpus * 4) - 1
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
        threads.append(Thread(target=send_message, args=(
            distribution, msg, ANALYSISD_QUEUE_SOCKET_PATH
        )))

    return threads


def detect_dropped_events():
    script_logger.info("Start detecting dropped events")
    while True:
        global stop_threads
        if stop_threads:
            break
        statistics_file_parsed = ConfigObj(ANALYSIS_STATISTICS_FILE)
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
    while True:
        global stop_threads
        if stop_threads:
            break
        script_logger.debug(f"Sending: {eps_distribution}")
        for _ in range(eps_distribution):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.connect(wazuh_socket)
            sock.send(message.encode())
            sock.close()
        sleep(1)


def run_threads(threads):
    for thread in threads:
        thread.start()
    while True:
        global stress_time
        if stress_time <= 0:
            global stop_threads
            stop_threads = True
            break
        else:
            stress_time -= 1
            sleep(1)
    file.truncate_file(ARCHIVES_LOG_FILE_PATH)


def main():
    global stress_time
    args = get_parameters()
    configure_logger(args)

    backup_internal_options = set_internal_options_conf(
        'analysisd.decode_event_queue_size',
        args.queue_size
    )

    stress_time = args.stress_time

    threads = create_threads(args.number_eps)

    start = time.perf_counter()
    run_threads(threads)
    end = time.perf_counter()
    total = int(end - start)
    script_logger.debug(f"EXECUTION TIME = {total}")

    analysisd_data = get_analysisd_data(args)

    if not args.output_file:
        script_logger.info(json.dumps(analysisd_data, indent=4))
    else:
        write_results_to_file(analysisd_data, args.output_file)

    set_internal_options_conf(restore_backup=backup_internal_options)


if __name__ == '__main__':
    main()

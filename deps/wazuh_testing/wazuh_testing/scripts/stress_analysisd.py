# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
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

if sys.platform == 'darwin':
    WAZUH_PATH = os.path.join("/", "Library", "Ossec")
else:
    WAZUH_PATH = os.path.join("/", "var", "ossec")
ANALYSISD_PROCESS_NAME = 'wazuh-analysisd'
ANALYSISD_STATISTICS_FILE = os.path.join(WAZUH_PATH, 'var', 'run', f'{ANALYSISD_PROCESS_NAME}.state')
ANALYSISD_QUEUE_SOCKET_PATH = os.path.join(WAZUH_PATH, 'queue', 'sockets', 'queue')
ARCHIVES_LOG_FILE_PATH = os.path.join(WAZUH_PATH, 'logs', 'archives', 'archives.log')
ALERTS_LOG_FILE_PATH = os.path.join(WAZUH_PATH, 'logs', 'alerts', 'alerts.log')
ALERTS_JSON_FILE_PATH = os.path.join(WAZUH_PATH, 'logs', 'alerts', 'alerts.json')
ANALYSISD_BINARY_PATH = os.path.join(WAZUH_PATH, 'bin', ANALYSISD_PROCESS_NAME)

msg = '0912:tmpdir:Dec  2 16:05:37 localhost su[6625]: pam_unix(su:session): '
'session opened for user root by vagrant(uid=0)'

process_timeout = 5
stop_command = f'pkill -f {ANALYSISD_PROCESS_NAME}'

script_logger = logging.getLogger('stress_manager')

events_decoded_list = []
events_dropped_list = []
stop_threads = False
thread_wait = 1
read_signal = False
stress_time = 0


def get_parameters():
    """Process the script parameters

    Returns:
        ArgumentParser: Parameters and their values
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--stress-time", type=int, required=False,
                        default=300, dest='stress_time',
                        help="Time in seconds to stress Analysisd")
    parser.add_argument("-e", "--number-eps", type=int, required=True,
                        dest='number_eps',
                        help="Time in seconds to stress Analysisd")
    parser.add_argument("-s", "--queue-size", type=int, required=False,
                        default=16384, dest='queue_size',
                        help="Size of Analysisd`s 'decode event' queue")
    parser.add_argument("-o", "--output-file", type=str,
                        help='The path of the file to which the results will be written.')
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


def set_internal_options_conf(options=None, restore_backup=None):
    if None not in (options, restore_backup):
        raise ValueError("Parameters: 'options' cannot be None if "
                         "'restore_backup' is None")

    new_content = ''
    backup = ''

    internal_options = os.path.join(WAZUH_PATH, 'etc', 'internal_options.conf')

    if restore_backup is not None:
        for line in restore_backup:
            new_content += line
    else:
        for option in list(options.keys()):
            with open(internal_options, 'r') as f:
                backup = lines = f.readlines()
                for line in lines:
                    new_line = line
                    if option in line:
                        new_line = f'{option}={options[option]}\n'
                    new_content += new_line
            with open(internal_options, 'w') as f:
                f.write(new_content)
            new_content = ''

    script_logger.info("Restarting analysisd")
    try:
        subprocess.run(stop_command.split())
        subprocess.run([ANALYSISD_BINARY_PATH])
    except subprocess.CalledProcessError as error:
        print(error.output)

    start_time = time.perf_counter()
    elapsed_time = 0
    running = False
    while elapsed_time < process_timeout:
        control_status_output = subprocess.run([f'{WAZUH_PATH}/bin/wazuh-control','status'],
            stdout=subprocess.PIPE).stdout.decode()
        analysisd_status_line = [line for line in control_status_output.splitlines() if 'analysisd' in line][0]
        status = ' '.join(analysisd_status_line.split()[1:])
        if status == 'is running...':
            running = True
            break
        elapsed_time = time.perf_counter() - start_time
    if not running:
        raise TimeoutError(f"{ANALYSISD_PROCESS_NAME} is not running")
    while not os.path.isfile(ANALYSISD_STATISTICS_FILE):
        pass
    script_logger.info("Analysisd started and statistics file ready.")

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
        'Queue size': params.queue_size,
        'Average': {
            'Decoded': '',
            'Dropped': ''
        },
        'Max': {
            'Decoded': '',
            'Dropped': ''
        },
        'Min': {
            'Decoded': '',
            'Dropped': ''
        }
    }

    events_sum = 0
    data = [events_decoded_list, events_dropped_list]

    for _, item in enumerate(data):
        key = list(results['Average'].keys())[_]
        data_set_len = len(item)
        if data_set_len == 0:
            raise BaseException("No data collected while stressing analysisd.")
        else:
            for events_number in item:
                events_sum += events_number
            results['Average'][key] = round(events_sum / data_set_len, 2)
            results['Max'][key] = max(item)
            results['Min'][key] = min(item)

    return results


def write_results_to_file(data, output_file_path):
    """Write the results in a file

    Args:
        data (dict): Analysisd data
        output_file_path (string): The path of the file to which the results will be written
    """
    output_dir = os.path.split(output_file_path)[0]

    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    with open(output_file_path, 'w') as file:
        file.write(json.dumps(data, indent=4))

    script_logger.info(f"The Analysisd data has been written in "
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
    quantity_of_threads = (usable_cpus * 4) - 2
    if eps <= quantity_of_threads or eps <= 200:
        quantity_of_threads = 0
        events_per_thread = eps
    else:
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
    if quantity_of_threads == 0:
        script_logger.info(f"Sender threads = 1")
    else:
        script_logger.info(f"Sender threads = {quantity_of_threads}")
    script_logger.info(f"Thread-EPS distributon = {distribution}")

    for _ in range(quantity_of_threads):
        threads.append(Thread(target=send_message, args=(
            distribution, msg, ANALYSISD_QUEUE_SOCKET_PATH
        )))
    threads.append(Thread(target=send_message, args=(
        distribution, msg, ANALYSISD_QUEUE_SOCKET_PATH, True # Final thread
    )))
    threads.append(Thread(target=detect_dropped_events))

    return threads


def detect_dropped_events():
    script_logger.info("Start detecting dropped events")
    while True:
        global stop_threads
        global read_signal

        if stop_threads:
            break
        while not os.path.isfile(ANALYSISD_STATISTICS_FILE):
            pass
        if read_signal:
            statistics_file_parsed = ConfigObj(ANALYSISD_STATISTICS_FILE)
            events_decoded = int(statistics_file_parsed['total_events_decoded'])
            events_dropped = int(statistics_file_parsed['events_dropped'])
            events_decoded_list.append(events_decoded)
            events_dropped_list.append(events_dropped)
            script_logger.debug(f"DECODED = {events_decoded}"
                f" --- DROPPED = {events_dropped}"
            )
            read_signal = False


def send_message(eps_distribution, message, wazuh_socket, final_thread=False):
    script_logger.info("Start sending events")
    start = 0
    end = 0
    while True:
        global stop_threads
        if stop_threads:
            break
        sleep(thread_wait - (end-start))
        start = time.perf_counter()
        for _ in range(eps_distribution):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.connect(wazuh_socket)
            sock.send(message.encode())
            sock.close()
        if final_thread:
            global read_signal
            read_signal = True
        end = time.perf_counter()


def run_threads(threads):
    for thread in threads:
        thread.start()
    while True:
        start = time.perf_counter()
        global stress_time
        if stress_time <= 0:
            global stop_threads
            stop_threads = True
            end = time.perf_counter()
            break
        else:
            end = time.perf_counter()
            sleep(thread_wait - (end - start))
            stress_time -= 1


def main():
    global stress_time
    args = get_parameters()
    configure_logger(args)

    options = {
        'analysisd.decode_event_queue_size': args.queue_size,
        'analysisd.state_interval': 1,
        'analysisd.decode_output_queue_size': args.queue_size
    }
    backup_internal_options = set_internal_options_conf(options)

    stress_time = args.stress_time

    threads = create_threads(args.number_eps)
    
    run_threads(threads)

    analysisd_data = get_analysisd_data(args)

    if not args.output_file:
        script_logger.info(json.dumps(analysisd_data, indent=4))
    else:
        write_results_to_file(analysisd_data, args.output_file)

    set_internal_options_conf(restore_backup=backup_internal_options)

    for file in [ARCHIVES_LOG_FILE_PATH, ALERTS_LOG_FILE_PATH, ALERTS_JSON_FILE_PATH]:
        with open(file, 'w'):
            pass


if __name__ == '__main__':
    main()

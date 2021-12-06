import socket
import time
from configobj import ConfigObj
import sys
from wazuh_testing.tools import ANALYSIS_STATISTICS_FILE, ANALYSISD_QUEUE_SOCKET_PATH
from threading import Thread

msg = '0912:tmpdir:Dec  2 16:05:37 localhost su[6625]: pam_unix(su:session): session opened for user root by vagrant(uid=0)'


class Injector():
    '''
    This class inject events per second to analysisd and detects dropping events
    '''
    def __init__(self, eps, execution_time):
        self.eps = eps
        self.quantity_of_threads = (eps + 1000 - 1) // 1000
        self.events_per_thread = self.eps // self.quantity_of_threads
        self.total_events_decoded = []
        self.total_events_dropped = []
        self.start_injector(float(execution_time))

    def detect_events_decoded(self, time_limit):
        drops_not_detected = True
        time_limit = float(time_limit)
        elapsed_time = 0.0
        while drops_not_detected:
            start = time.time()
            cfg = ConfigObj(ANALYSIS_STATISTICS_FILE)
            total_events_decoded = int(cfg['total_events_decoded'])
            events_dropped = int(cfg['events_dropped'])
            print(f'Total decoded: {total_events_decoded}')
            print(f'Total events_dropped: {events_dropped}')
            if total_events_decoded > 0:
                self.total_events_decoded.append(total_events_decoded)
            if events_dropped > 0:
                self.total_events_dropped.append(events_dropped)
                drops_not_detected = False

            end = time.time()
            elapsed_time = elapsed_time + (end - start)
            print(elapsed_time, end='\n')
            if elapsed_time >= time_limit: # Stop the thread if elapsed time reach the time limit
                drops_not_detected = False
            time.sleep(1)

    def send_message(self, message, wazuh_socket):
        for i in range(0, self.events_per_thread):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.connect(wazuh_socket)
            sock.send(message.encode())
            sock.close()

    def start_injector(self, expected_execution_time):
        actual_execution_time = 0.0
        while actual_execution_time < expected_execution_time:
            start = time.time()
            threads = []
            for i in range(0, self.quantity_of_threads):
                threads.append(Thread(target=self.send_message, args=(msg, ANALYSISD_QUEUE_SOCKET_PATH)))
                if i == 0:
                    threads.append(Thread(target=self.detect_events_decoded, kwargs={'time_limit': expected_execution_time}))
                    threads[i+1].start()

            for i, thread in enumerate(threads):
                if i == 1:
                    continue
                else:
                    thread.start()

            for thread in threads:
                thread.join(timeout=10)
            end = time.time()
            actual_execution_time += end - start


        return self.total_events_decoded, self.total_events_dropped
